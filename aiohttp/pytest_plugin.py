import asyncio
import contextlib

import pytest
from aiohttp.web import Application

from .test_utils import (TestClient, loop_context, setup_test_loop,
                         teardown_test_loop, unused_port)


try:
    import uvloop
except ImportError:
    uvloop = None


@contextlib.contextmanager
def _passthrough_loop_context(loop):
    if loop:
        # loop already exists, pass it straight through
        yield loop
    else:
        # this shadows loop_context's standard behavior
        loop = setup_test_loop()
        yield loop
        teardown_test_loop(loop)


def pytest_pycollect_makeitem(collector, name, obj):
    """
    Fix pytest collecting for coroutines.
    """
    if collector.funcnamefilter(name) and asyncio.iscoroutinefunction(obj):
        return list(collector._genfunctions(name, obj))


def pytest_pyfunc_call(pyfuncitem):
    """
    Run coroutines in an event loop instead of a normal function call.
    """
    if asyncio.iscoroutinefunction(pyfuncitem.function):
        existing_loop = pyfuncitem.funcargs.get('loop', None)
        with _passthrough_loop_context(existing_loop) as _loop:
            testargs = {arg: pyfuncitem.funcargs[arg]
                        for arg in pyfuncitem._fixtureinfo.argnames}

            task = _loop.create_task(pyfuncitem.obj(**testargs))
            _loop.run_until_complete(task)

        return True


def pytest_addoption(parser):
    parser.addoption("--loop_library", choices=['asyncio', 'uvloop'],
                     default='asyncio',
                     help=("Used event loop implementation\n."
                           "asyncio by default.\n"
                           "Available values: asyncio, uvloop, all"))


def pytest_generate_tests(metafunc):
    if 'loop_library' in metafunc.fixturenames:
        loop_library = metafunc.config.option.loop_library
        if loop_library == 'asyncio':
            libs = [asyncio]
        elif loop_library == 'uvloop':
            libs = [uvloop]
        elif loop_library == 'all':
            libs = [asyncio, uvloop]
        else:
            raise RuntimeError('Unsupported --loop_library value')
        if None in libs:
            raise RuntimeError('Not all --loop_library libs are installed.\n'
                               'Try pip install uvloop')
        metafunc.parametrize("loop_library", libs, scope='session')


# add the unused_port fixture
unused_port = pytest.fixture(unused_port)


@pytest.yield_fixture
def loop():
    """Event loop instance"""
    with loop_context() as loop:
        yield loop


@pytest.yield_fixture
def test_client(loop):
    """Test HTTP client"""
    clients = []

    @asyncio.coroutine
    def _create_from_app_factory(app_or_factory, *args, **kwargs):
        if not isinstance(app_or_factory, Application):
            app = app_or_factory(loop, *args, **kwargs)
        else:
            assert not args, "args should be empty"
            assert not kwargs, "kwargs should be empty"
            app = app_or_factory

        assert app.loop is loop, \
            "Application is attached to other event loop"

        client = TestClient(app)
        yield from client.start_server()
        clients.append(client)
        return client

    yield _create_from_app_factory

    while clients:
        clients.pop().close()
