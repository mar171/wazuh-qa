import os
import sys
import logging
import time
import uuid

common_logger_handler = logging.StreamHandler(sys.stdout)
common_logger_handler.setFormatter(logging.Formatter("%(asctime)s — %(levelname)s — %(message)s"))


class FileStress:
    def __init__(self, path, debug):
        self.path = path
        self.events = 0
        self.filename_counter = 0
        self.stop_file_stress = False

        logger_name = 'FileStress'
        self.logger = logging.getLogger(logger_name)
        self.logger.setLevel(logging.DEBUG if debug else logging.INFO)
        self.logger.addHandler(common_logger_handler)

    def list_files(self, regex=None):
        return os.listdir(self.path)

    def create_file(self, filepath):
        try:
            open(filepath, 'w+').close()
        except OSError as error:
            self.logger.error(f"Error creating file: {error}")
            exit(-1)

    def create_files(self, number_of_files, filename='file', subpath=None):
        file_created = []

        for _ in range(number_of_files):
            new_id = str(uuid.uuid4())
            file_name = f"{filename}-{new_id}-{self.filename_counter}"
            filepath = os.path.join(self.path, file_name)
            self.create_file(filepath)
            self.filename_counter += 1
            file_created.append(file_name)

        return file_created

    def modify_file(self, filepath, content, mode='a'):
        try:
            with open(filepath, mode) as f:
                f.write(content)
        except OSError as error:
            self.logger.error(f"Error modifying file: {error}")
            exit(-1)

    def modify_files(self, file_writer_dict):
        for file, variables in file_writer_dict.items():
            with open(os.path.join(self.path, file), variables.get('mode', 'a')) as file_operator:
                file_operator.write(variables['content'])
                self.events += 1

    def delete_file(self, file):
        try:
            os.remove(os.path.join(self.path, file))
        except OSError as error:
            self.logger.error(f"Error deleting file: {error}")
            exit(-1)

    def delete_files(self, files_to_delete):
        for file in files_to_delete:
            self.delete_file(os.path.join(self.path, file))

    def start_file_stress(self, epi_file_creation, epi_file_update, epi_file_deletion, event, interval=1,
                          filename='file', use_preexisting_files=False, add_counter_to_events=True):
        if use_preexisting_files:
            self.logger.info("Using preexisting files.")
            preexisting_files = list_files()

        if (epi_file_creation < epi_file_update or epi_file_creation < epi_file_deletion) and not use_preexisting_files:
            self.logger.error("ERROR: EPS of file creation is lower than EPS of file update or deletion.")
            exit(-1)

        while True and not self.stop_file_stress:
            # If EPS created files < modified or deleted --> Error, use preexisting files option
            # Otherwise use created files in each interval to generate delete and mofified alerts

            # EPI file creation
            list_files = self.create_files(epi_file_creation, filename)
            if use_preexisting_files:
                list_files = preexisting_files

            # EPI file update
            n_update_events = 0

            file_writer_dict = {}
            for _ in range(epi_file_update):
                for file in list_files:
                    new_line = f"{event}-{self.events}\n" if add_counter_to_events else f"{event}\n"
                    if not file_writer_dict.get(file):
                        file_writer_dict[file] = {'content': new_line , 'mode': 'a'}
                    else:
                        file_writer_dict[file]['content'] += new_line

                    n_update_events += 1
                    self.events += 1

                if n_update_events >= epi_file_update:
                    break

            self.modify_files(file_writer_dict)

            # EPI file deletion
            if use_preexisting_files:
                list_files = list_files()
            if len(list_files) < epi_file_deletion:
                self.logger.error("ERROR: Number of files to delete is higher than the number of files in the directory.")
                exit(-1)

            files_to_delete = list_files[:epi_file_deletion]
            self.delete_files(files_to_delete)

            time.sleep(interval)

    def stop(self):
        self.stop_file_stress = True
