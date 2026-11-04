import pytest

from aether.core.models import ModuleResult
from aether.core.module_loader import ModuleLoader
from aether.core.plugin import Module, ModuleMeta, RunContext


class SampleModule(Module):
    meta = ModuleMeta(identifier="sample.one", category="recon")

    async def run(self, context: RunContext) -> ModuleResult:
        return ModuleResult(module=self.identifier)


class OtherModule(Module):
    meta = ModuleMeta(identifier="sample.two")

    async def run(self, context: RunContext) -> ModuleResult:
        return ModuleResult(module=self.identifier)


def test_module_without_meta_is_rejected():
    with pytest.raises(TypeError):

        class Bad(Module):  # noqa: D401 - no meta
            async def run(self, context):
                return ModuleResult(module="bad")


def test_register_and_create():
    loader = ModuleLoader()
    loader.register(SampleModule)
    assert "sample.one" in loader
    inst = loader.create("sample.one")
    assert isinstance(inst, SampleModule)
    assert len(loader) == 1


def test_duplicate_identifier_rejected():
    loader = ModuleLoader()
    loader.register(SampleModule)

    class Clash(Module):
        meta = ModuleMeta(identifier="sample.one")

        async def run(self, context):
            return ModuleResult(module="clash")

    with pytest.raises(ValueError, match="duplicate"):
        loader.register(Clash)


def test_register_same_class_twice_is_idempotent():
    loader = ModuleLoader()
    loader.register(SampleModule)
    loader.register(SampleModule)  # same class, fine
    assert len(loader) == 1


def test_register_non_module_rejected():
    loader = ModuleLoader()
    with pytest.raises(TypeError):
        loader.register(object)  # type: ignore[arg-type]
