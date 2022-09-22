import json
import argparse
import wazuh_testing.tools.configuration as conf

def main():
    arg_parser = argparse.ArgumentParser()

    arg_parser.add_argument('-c', '--configuration-file', metavar='configuration', type=str, required=True,
                            default=None, help='Configuration', dest='configuration_file')

    args = arg_parser.parse_args()


    with open(args.configuration_file) as f:
        configuration = f.read()
        new_configuration = json.loads(configuration)

        new_ossec_configuration = conf.set_section_wazuh_conf(new_configuration)
        conf.write_wazuh_conf(new_ossec_configuration)


if __name__ == "__main__":
    main()
