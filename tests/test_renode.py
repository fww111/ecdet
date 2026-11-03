from pathlib import Path
import re
import subprocess
from types import SimpleNamespace

import pytest

from ecdet.l3_analysis.dynamic import renode


@pytest.fixture
def files(tmp_path):
    firmware=tmp_path/'firmware.elf';firmware.write_bytes(b'\x7fELFtest')
    platform=tmp_path/'board.repl';platform.write_text('cpu: CPU.CortexM @ sysbus\n')
    return firmware,platform,tmp_path/'reports'


def install_fake(monkeypatch, *, uart='BOOT\nOK\n', stdout='', rc=0, complete=True):
    monkeypatch.setattr(renode,'find_renode',lambda binary=None: str(Path(__file__).resolve()))
    def run(command,**kwargs):
        if '--version' in command:
            return SimpleNamespace(stdout='Fake test runtime',stderr='',returncode=0)
        # The generated script path is the escaped Renode include argument.
        script=Path(command[-1].removeprefix('include @').replace('\\ ', ' '))
        text=script.read_text(encoding='utf-8')
        marker=re.search(r'echo "([A-Za-z0-9_]+)"',text).group(1)
        if uart is not None:(script.parent/'uart.log').write_text(uart,encoding='utf-8')
        return SimpleNamespace(stdout=stdout+('\n'+marker+'\n' if complete else ''),stderr='',returncode=rc)
    monkeypatch.setattr(renode.subprocess,'run',run)


def test_valid_uart_and_completion(files,monkeypatch):
    install_fake(monkeypatch)
    result=renode.RenodeRunner().run(*files,expected=['BOOT','OK'],uart_input=b's')
    assert result.status=='PASS' and result.execution_completed
    assert result.uart_input_hex=='73' and not result.alerts()
    assert result.firmware_sha256 and result.platform_sha256
    assert Path(result.run_dir,'result.json').is_file()
    assert 'WriteChar 115' in Path(result.script).read_text()


def test_uart_failure_emits_independent_alert(files,monkeypatch):
    install_fake(monkeypatch,uart='BOOT\nFAILED\n')
    result=renode.RenodeRunner().run(*files,expected=['BOOT'],failure_markers=['FAILED'])
    assert result.status=='FAIL'
    alert,=result.alerts()
    assert alert.engine=='renode' and alert.location.path=='firmware.elf'
    assert alert.provenance.value=='detected'


def test_stdout_or_script_echo_cannot_satisfy_uart(files,monkeypatch):
    install_fake(monkeypatch,uart='BOOT\n',stdout='OK\nFAILED\n')
    result=renode.RenodeRunner().run(*files,expected=['OK'],failure_markers=['FAILED'])
    assert result.status=='FAIL' and result.missing_expected==['OK']
    assert not result.alerts()


@pytest.mark.parametrize('uart', ['', 'BOOT\nOK\n'])
def test_incomplete_script_never_passes(files,monkeypatch,uart):
    install_fake(monkeypatch,uart=uart,complete=False)
    result=renode.RenodeRunner().run(*files,expected=['OK'])
    assert result.status=='ERROR' and not result.alerts()


def test_missing_uart_is_error(files,monkeypatch):
    install_fake(monkeypatch,uart=None)
    result=renode.RenodeRunner().run(*files,expected=['OK'])
    assert result.status=='ERROR'


def test_nonzero_exit_not_a_firmware_bug(files,monkeypatch):
    install_fake(monkeypatch,uart='FAILED',rc=1)
    result=renode.RenodeRunner().run(*files,failure_markers=['FAILED'])
    assert result.status=='ERROR' and not result.alerts()


def test_timeout_is_recorded_not_a_firmware_bug(files,monkeypatch):
    monkeypatch.setattr(renode,'find_renode',lambda binary=None: str(Path(__file__).resolve()))
    def timed_out(*args,**kwargs):
        raise subprocess.TimeoutExpired(args[0],.1,output=b'partial',stderr=b'timeout')
    monkeypatch.setattr(renode.subprocess,'run',timed_out)
    result=renode.RenodeRunner(timeout=.1).run(*files,expected=['OK'])
    assert result.status=='TIMEOUT' and not result.alerts()
    assert Path(result.stdout_log).read_text()=='partial'


def test_missing_runtime(files,monkeypatch):
    monkeypatch.setattr(renode,'find_renode',lambda binary=None: None)
    result=renode.RenodeRunner().run(*files,expected=['OK'])
    assert result.status=='NOT_AVAILABLE'


@pytest.mark.parametrize('changes',[
    {'uart':'sysbus.usart2\nquit'}, {'virtual_seconds':-1}, {'virtual_seconds':float('nan')},
    {'virtual_seconds':True},{'expected':[]},{'expected':['']},{'expected':['x\ny']},
    {'expected':'OK'},{'expected':None},{'failure_markers':'BAD'},
    {'uart_input':'s'},{'uart_input':b'x'*4097},
])
def test_invalid_run_arguments(files,changes):
    kwargs={'expected':['OK'],**changes}
    assert renode.RenodeRunner().run(*files,**kwargs).status=='INVALID_INPUT'


def test_invalid_elf_and_platform(files):
    files[0].write_bytes(b'bad')
    assert renode.RenodeRunner().run(*files,expected=['OK']).status=='INVALID_INPUT'
    files[0].write_bytes(b'\x7fELF')
    files[1].unlink()
    assert renode.RenodeRunner().run(*files,expected=['OK']).status=='INVALID_INPUT'


@pytest.mark.parametrize('timeout',[0,-1,float('inf'),True])
def test_invalid_timeout(timeout):
    with pytest.raises(ValueError):renode.RenodeRunner(timeout=timeout)


def test_independent_runs_cannot_reuse_uart(files,monkeypatch):
    install_fake(monkeypatch)
    first=renode.RenodeRunner().run(*files,expected=['OK'])
    install_fake(monkeypatch,uart=None)
    second=renode.RenodeRunner().run(*files,expected=['OK'])
    assert first.status=='PASS' and second.status=='ERROR'
    assert first.run_dir!=second.run_dir


def test_configured_runtime_used_consistently(tmp_path,monkeypatch):
    binary=tmp_path/'renode.exe';binary.write_text('fixture')
    monkeypatch.setenv('ECDET_RENODE',str(binary))
    assert renode.find_renode()==str(binary)
    assert renode.find_renode(str(tmp_path/'absent')) is None


def test_paths_with_spaces(files,monkeypatch):
    install_fake(monkeypatch)
    result=renode.RenodeRunner().run(files[0],files[1],files[2]/'space dir',expected=['OK'])
    assert result.status=='PASS' and '\\ ' in result.command[-1]


def test_changed_firmware_cannot_be_a_verified_result(files,monkeypatch):
    install_fake(monkeypatch)
    runner=renode.subprocess.run
    def mutate(command,**kwargs):
        result=runner(command,**kwargs)
        if '--version' not in command:files[0].write_bytes(b'\x7fELFchanged')
        return result
    monkeypatch.setattr(renode.subprocess,'run',mutate)
    result=renode.RenodeRunner().run(*files,expected=['OK'],failure_markers=['BAD'])
    assert result.status=='ERROR' and not result.alerts()
