import configparser

class ConfigManager:
	_config = configparser.ConfigParser()
	_config_file = "sdp_config.ini"
	_fuzz_iteration = 5000
	_restart_bluetooth=True
	_random_fuzzing=True
	_scan_duration=6
	_garbage_list=True
	@staticmethod
	def load_config(file_path=None):
		"""Loads the INI configuration file."""
		if file_path:
			ConfigManager._config_file = file_path
		ConfigManager._config.read(ConfigManager._config_file)
		ConfigManager._fuzz_iteration = ConfigManager._config.getint("settings", "fuzz_iteration", fallback=5000)
		ConfigManager._restart_bluetooth = ConfigManager._config.getboolean("settings", "restart_bluetooth", fallback=True)
		ConfigManager._random_fuzzing = ConfigManager._config.getboolean("settings", "random_fuzzing", fallback=True)
		ConfigManager._scan_duration = ConfigManager._config.getint("settings", "scan_duration", fallback=6)
		ConfigManager._garbage_list = ConfigManager._config.getboolean("settings", "garbage_list", fallback=True)

		ConfigManager.debug_config()

			
	@staticmethod
	def debug_config():
		print(f'Fuzz iteration: {ConfigManager._fuzz_iteration}')
		print(f'Restart Bluetooth: {ConfigManager._restart_bluetooth}')
		print(f'Random Fuzzing: {ConfigManager._random_fuzzing}')
		print(f'_scan_duration: {ConfigManager._scan_duration}')
	@staticmethod
	def get_fuzz_iteration():
		return ConfigManager._fuzz_iteration

	@staticmethod
	def get_restart_bluetooth():
		return ConfigManager._restart_bluetooth

	@staticmethod
	def get_random_fuzzing():
		return ConfigManager._random_fuzzing

	@staticmethod
	def get_scan_duration():
		return ConfigManager._scan_duration

	@staticmethod
	def get_to_fuzz_garbage_list():
		return ConfigManager._garbage_list


