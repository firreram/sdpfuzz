import configparser

class ConfigManager:
	_config = configparser.ConfigParser()
	_config_file = "config.ini"
	_fuzz_iteration = 5000
	_restart_bluetooth=True
	_random_fuzzing=True
	_scan_duration=6
	@staticmethod
	def load_config(file_path=None):
		"""Loads the INI configuration file."""
		try:
			if file_path:
				ConfigManager._config_file = file_path
			ConfigManager._config.read(ConfigManager._config_file)
			_fuzz_iteration = ConfigManager._config.getint("settings", "fuzz_iteration", fallback=5000)
			_restart_bluetooth = ConfigManager._config.getboolean("settings", "fuzz_iteration", fallback=True)
			_random_fuzzing = ConfigManager._config.getboolean("settings", "random_fuzzing", fallback=True)
			_scan_duration = ConfigManager._config.getint("settings", "scan_duration", fallback=6)
		except:
			pass

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


