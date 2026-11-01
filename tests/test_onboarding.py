import unittest
import sys
from pathlib import Path
from unittest.mock import Mock,patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
import onboarding

class OnboardingTests(unittest.TestCase):
    def test_unconfigured_never_ready(self):
        with patch.object(onboarding,'Router',side_effect=ValueError('setup required')):
            result=onboarding.inspect_router()
        self.assertFalse(result['ready'])
    def test_supported_router_requires_preflight(self):
        router=Mock();router.request.return_value={'architecture-name':'arm64','version':'7.23.7'}
        with patch.object(onboarding,'Router',return_value=router),patch.object(onboarding,'preflight',side_effect=ValueError('route missing')):
            self.assertFalse(onboarding.inspect_router()['ready'])
    def test_unsupported_architecture_stops(self):
        router=Mock();router.request.return_value={'architecture-name':'mipsbe','version':'7.23.7'}
        with patch.object(onboarding,'Router',return_value=router),patch.object(onboarding,'preflight') as check:
            self.assertFalse(onboarding.inspect_router()['ready']);check.assert_not_called()
    def test_ready_requires_successful_checks(self):
        router=Mock();router.request.return_value=[{'architecture-name':'arm64','version':'7.23.7'}]
        with patch.object(onboarding,'Router',return_value=router),patch.object(onboarding,'preflight'):
            self.assertTrue(onboarding.inspect_router()['ready'])
        self.assertTrue(all(c.args[0]=='GET' for c in router.request.call_args_list))
