import os
import sys
import logging
import time
import uuid

common_logger_handler = logging.StreamHandler(sys.stdout)
common_logger_handler.setFormatter(logging.Formatter("%(asctime)s — FileStress  — %(levelname)s  —  %(message)s"))

class FileStress:
    def __init__(self, path_list, debug):
        self.path_list = path_list
        self.events = 0
        self.filename_counter = 0
        self.stop_file_stress = False

        logger_name = 'FileStress'
        self.logger = logging.getLogger(logger_name)
        self.logger.setLevel(logging.DEBUG if debug else logging.INFO)
        self.logger.addHandler(common_logger_handler)

    def list_files(self, regex=None):
        file_list = []
        for directory in self.path_list:
            for file in os.listdir(directory):
                file_list.append(os.path.join(directory, file))

        return file_list

    def create_file(self, filepath):
        try:
            self.logger.debug(f"Creating file {filepath}")
            open(filepath, 'w+').close()
        except OSError as error:
            self.logger.error(f"Error creating file: {error}")
            exit(-1)

    def create_files(self, number_of_files, filename='file'):
        file_created = []
        n_directories = len(self.path_list)

        for file_index in range(number_of_files):
            new_id = str(uuid.uuid4())
            file_name = f"{filename}-{new_id}-{self.filename_counter}"

            filepath = os.path.join(self.path_list[self.filename_counter%n_directories], file_name)
            self.create_file(filepath)
            self.filename_counter += 1
            file_created.append(file_name)

        return file_created

    def modify_file(self, filepath, content, mode='a'):
        try:
            with open(filepath, mode) as f:
                self.logger.debug(f"Writing in {filepath} content {content}")
                f.write(content)
        except OSError as error:
            self.logger.error(f"Error modifying file: {error}")
            exit(-1)

    def modify_files(self, file_writer_dict):
        for file, variables in file_writer_dict.items():
            with open(file,'a') as file_operator:
                for line in variables['content']:
                    file_operator.write(line)
                    self.events += 1

    def delete_file(self, filepath):
        try:
            self.logger.debug(f"Deleting {filepath}")
            os.remove(filepath)
        except OSError as error:
            self.logger.error(f"Error deleting file: {error}")
            exit(-1)

    def delete_files(self, files_to_delete):
        for file in files_to_delete:
            self.delete_file(file)

    def start_file_stress(self, epi_file_creation, epi_file_update, epi_file_deletion, event, interval=1,
                          filename='file', add_counter_to_events=True):

        self.logger.info(f"Starting file stress process")
        use_preexisting_files = False
        if (epi_file_creation < epi_file_update or epi_file_creation < epi_file_deletion):
            self.logger.info("Using preexisting files")
            use_preexisting_files = True
            preexisting_files = self.list_files()
            self.logger.debug(f"{preexisting_files}")


        while not self.stop_file_stress:
            # EPI file creation
            self.logger.info(f"Creating {epi_file_creation} events")
            path_files = self.create_files(epi_file_creation, filename)
            if use_preexisting_files:
                path_files = preexisting_files

            # EPI file update
            n_update_events = 0

            self.logger.info(f"Creating {epi_file_update} events")
            file_writer_dict = {}
            for _ in range(epi_file_update):
                for file in path_files:
                    new_line = f"{event}\n"
                    if not file_writer_dict.get(file):
                        file_writer_dict[file] = {'content': [new_line], 'mode': 'a'}
                    else:
                        file_writer_dict[file]['content'] += [new_line]

                    n_update_events += 1
                    self.events += 1

                    if n_update_events >= epi_file_update:
                        break
                if n_update_events >= epi_file_update:
                    break

            self.modify_files(file_writer_dict)

            # EPI file deletion
            self.logger.info(f"Creating {epi_file_deletion} events")
            if use_preexisting_files:
                path_files = self.list_files()

            if len(path_files) < epi_file_deletion:
                self.logger.error("ERROR: Number of files to delete is higher than the number of files in"
                                  "the directory.")
                exit(-1)

            files_to_delete = path_files[:epi_file_deletion]
            self.delete_files(files_to_delete)

            time.sleep(interval)

    def stop(self):
        self.logger.info("Stopping all file_stress processes")
        self.stop_file_stress = True
