PARAMETERS = ['first_report', 'second_report']

def pytest_addoption(parser):
    for param in PARAMETERS:
        parser.addoption(f"--{param}", action='store', default=f"{param}")

def pytest_generate_tests(metafunc):
    for param in PARAMETERS:
        option_value = metafunc.config.getoption(param)
        if param in metafunc.fixturenames and option_value is not None:
            metafunc.parametrize(param, [option_value])
