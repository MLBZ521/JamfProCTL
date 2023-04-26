#!/usr/bin/env python3

from __future__ import annotations # Fix circular type hinting

import base64
import contextlib
import functools
import os
import sys
import re

# For Type Hinting
import io
from pathlib import PurePath
from typing import Iterable, Optional, Union
PathTypes = Union[str, bytes, PurePath]

import jasypt4py
import mysql.connector
import paramiko
import scp
import sshtunnel
import yaml

from Cryptodome.Hash import SHA256
from Cryptodome.Cipher import AES
from Cryptodome.Util import Padding

from pydantic import BaseModel


__about__ = "https://github.com/MLBZ521/JamfProCTL"
__created__ = "4/21/2023"
__updated__ = "4/26/2023"
__version__ = "1.2.0"


class MySQLClient():
	"""A class that sets up a connection to a MySQL Server.

	Supports SSHing to the server first, then initializing the MySQL connection.

	Can also be used as a Context Manager to interact with a MySQL database."""

	def __init__(self,
		server: DB_Server,
		remote_bind_address: str = "127.0.0.1",
		local_bind_address: str = "127.0.0.1",
		dictionary: bool = True,
		verbose: bool = True
	):

		self.server = server
		self.remote_bind_address = remote_bind_address
		self.local_bind_address = local_bind_address
		self.dictionary = dictionary
		self.verbose = verbose

		self.hostname = self.server.hostname
		self.ip = self.server.ip
		self.ssh_port = self.server.ssh.port
		self.ssh_username = self.server.ssh.username
		self.ssh_password = self.server.ssh.password
		self.ssh_key = self.server.ssh.ssh_key
		self.database_username = self.server.database.username
		self.database_password = self.server.database.password
		self.database_name = self.server.database.name
		self.database_port = self.server.database.port
		self.allow_agent = self.server.allow_agent
		self.use_ssh = self.server.use_ssh
		self.ssh_timeout = self.server.ssh.timeout
		self.database_timeout = self.server.database.timeout

		self.db_connection = None
		self.db_cursor = None
		self.tunnel = None


	def init_tunnel(self):
		"""Initialize and start SSH Tunnel"""

		if self.use_ssh:

			self.__verbose__(
				f"Setting up SSH Tunnel into host `{self.hostname}`...",
				end=""
			)

		try:

			sshtunnel.SSH_TIMEOUT = self.ssh_timeout

			self.tunnel = sshtunnel.SSHTunnelForwarder(
				ssh_address_or_host = (self.ip or self.hostname, self.ssh_port),
				ssh_username = self.ssh_username,
				ssh_password = self.ssh_password,
				ssh_pkey = self.ssh_key,
				remote_bind_address = (self.remote_bind_address, self.database_port),
				local_bind_address = (self.local_bind_address, self.database_port),
				allow_agent = self.allow_agent
			)

			self.tunnel.start()
			self.__verbose__("Connected!")

		except TimeoutError as error:
			self.__verbose__("Failed!")
			print(error)


	def init_database(self):
		"""Starts a connection to the database."""

		self.__verbose__(
			f"Connecting to the `{self.database_name}` database on host `{self.hostname}`...",
			end=""
		)

		try:

			self.db_connection = mysql.connector.MySQLConnection(
				host = self.tunnel.local_bind_host if self.use_ssh and \
					self.tunnel else self.hostname,
				user = self.database_username,
				password = self.database_password,
				db = self.database_name,
				port = self.database_port,
				connection_timeout = self.database_timeout
			)

			self.__verbose__("Connected!")
			self.db_cursor = self.db_connection.cursor(buffered=True, dictionary=self.dictionary)

		except TimeoutError as error:
			self.__verbose__("Failed!")
			print(error)


	def __enter__(self):
		"""Context Manager for a database connection.

		Returns:
			db_cursor:  A database cursor instance
		"""

		self.init_database()
		return self.db_cursor


	def __exit__(self, exc_type, exc_value, exc_traceback):
		"""Commits and closing connection to the database"""

		# Commit the transaction
		# self.db_connection.commit()
		# Not needed as only supportING SELECT statements at this time

		self.close()


	def __verbose__(self, message: str, end: str = "\n", file: io.TextIOWrapper = sys.stdout):
		"""Handles verbose messaging

		Args:
			message (str):  A message to be printed.
			end (str, optional):  A string that will be appended after the last value of `message`.
				Defaults to newline (i.e. `\\n`).
			file (file-like object (stream), optional):  Where the message will be sent.
				Defaults to the current sys.stdout.
		"""

		if self.verbose:
			print(
				f"{TextFormat.bold}[Verbose]{TextFormat.end} {message}",
				end = end,
				file = file
			)


	def close(self):
		"""Close open database connection and SSH Tunnel"""

		if self.db_cursor:
			# Close the cursor
			self.db_cursor.close()

		if self.db_connection:
			# Close the connection
			self.db_connection.close()
			self.__verbose__("Closed DB Connection!")

		if self.tunnel and self.tunnel.is_active:
			self.tunnel.close()
			self.__verbose__("Closed SSH Tunnel!")


	def reconnect(self):
		"""Checks database and SSH tunnel connections and
		reestablishes the connections if they are not active."""

		if self.use_ssh:

			if not self.tunnel:
				self.__verbose__("Tunnel not established")
				self.init_tunnel()

			elif not self.tunnel.is_active:
				self.__verbose__("Tunnel is not active")
				self.tunnel.restart()

		if not self.db_connection or not self.db_cursor:
			self.__verbose__("Database connection not established")
			self.init_database()

		if not self.db_connection.is_connected():
			self.__verbose__("Database connection is not active")
			self.db_connection.reconnect()


	def query(self, query_statement: str, close_ssh: bool = True):
		"""Internal method to query the database.

		Args:
			query_statement (str):  A SQL formatted query statement.
			close_ssh (bool, optional):  Whether or not the SSH Tunnel should be closed
				after the query is performed. Defaults to True.

		Returns:
			(dict, dict):  Two dict's are returned, one of the SQL query results, the other a dict
				containing meta data of the results (specifically the row count and column names).
		"""

		self.reconnect()

		self.db_cursor.execute(f"{query_statement}")
		results = self.db_cursor.fetchall()
		meta_data = {
			"rowcount": self.db_cursor.rowcount, "column_names": self.db_cursor.column_names }

		# if self.use_ssh and close_ssh:
		# 	self.tunnel.close()

		return results, meta_data


class SSHClient():
	"""A class that sets up a SSH Client connection.

	Can also be used as a Context Manager."""

	def __init__(self, server: App_Server, verbose: bool = True):

		self.server = server
		self.verbose = verbose

		self.hostname = self.server.hostname
		self.ip = self.server.ip
		self.port = self.server.ssh.port
		self.username = self.server.ssh.username
		self.password = self.server.ssh.password
		self.ssh_key = self.server.ssh.ssh_key
		self.look_for_keys = self.server.ssh.look_for_keys
		self.timeout = self.server.ssh.timeout

		self.stdin = None
		self.stdout = None
		self.stderr = None
		# self.sftp = None

		# Initialize Paramiko SSH Client
		self.client = paramiko.SSHClient()
		self.client.load_host_keys(os.path.expanduser("~/.ssh/known_hosts"))
		self.client.load_system_host_keys()
		self.client.set_missing_host_key_policy(paramiko.WarningPolicy())
		# self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())


	def __enter__(self):
		"""Context Manager method to start SSH Client connection to the host.

		Returns:
			ssh client:  A SSHClient instance.
		"""

		self.start()
		return self


	def __exit__(self, exc_type, exc_value, exc_traceback):
		"""Context Manager method to handle exiting."""

		self.close()


	def __verbose__(self, message: str, end: str = "\n", file: io.TextIOWrapper = sys.stdout):
		"""Handles verbose messaging

		Args:
			message (str):  A message to be printed.
			end (str, optional):  A string that will be appended after the last value of `message`.
				Defaults to newline (i.e. `\\n`).
			file (file-like object (stream), optional):  Where the message will be sent.
				Defaults to the current sys.stdout.
		"""

		if self.verbose:
			print(
				f"{TextFormat.bold}[Verbose]{TextFormat.end} {message}",
				end = end,
				file = file
			)


	def __decode_output(self, output: bytes):
		"""Helper method to handle decoding output from an SSH Client's exec_command method.

		Args:
			output (binary):  A binary encoded string.

		Returns:
			str:  Decoded string.
		"""

		if output:
			return output.read().decode("utf-8")


	def __start_ssh(func):
		"""A decorator to start the SSH Client if it is not currently active.

		Not to be called directly.

		Args:
			func (callable):  A function or other callable that will be executed.

		Returns:
			any:  Results of the passed function.
		"""

		@functools.wraps(func)
		def wrap(self, *args, **kwargs):
			"""Standard decorator function."""

			if not self.active():
				self.__verbose__("Tunnel is not active")
				self.start()

			result = func(self, *args, **kwargs)

			if "close_ssh" in kwargs and kwargs["close_ssh"]:
				self.__verbose__("SSH should be closed!")
				# self.close()

			return result
		return wrap


	def __scp_progress(self, filename: str, size: int, sent: int):
		"""Helper function to provide current progress status of a download or upload transfer.

		Args:
			filename (str):  The filename that is currently being transferred.
			size (int):  Size of the file being transferred.
			sent (int):  Current amount of data that has been transferred.
		"""
		percentage = float(sent)/float(size)*100
		filename = filename if isinstance(filename, str) else filename.decode("utf-8")
		sys.stdout.write(f"`{self.hostname}`:`{filename}` | Progress:  {percentage:.2f}% \r" )


	def active(self):
		"""Determine if the SSH Tunnel is currently open.

		Returns:
			bool:  Returns True if the tunnel is open/connected.
		"""

		try:
			return self.client.get_transport().is_active()
		except AttributeError:
			return False


	def close(self):
		"""Handles closing the SSH Tunnel"""

		if self.stdin:
			self.stdin.close()
		if self.stdout:
			self.stdout.close()
		if self.stderr:
			self.stderr.close()
		# if self.sftp:
		# 	self.sftp.close()
		if self.active():
			self.client.close()
			self.__verbose__("SSHClient closed!")


	@__start_ssh
	def execute_cmd(self, cmd: str):
		"""Helper method to execute an SSH Client's exec_command method.

		Args:
			cmd (str):  A command to execute on a remote host.

		Returns:
			tuple:  Tuple containing (stdout: str, stderr: str, exit_status: int)
		"""

		self.__verbose__(f"Executing Command:  `{cmd}`")
		self.stdin, self.stdout, self.stderr = self.client.exec_command(cmd)
		exit_status = self.stdout.channel.recv_exit_status()
		stdout = self.__decode_output(self.stdout)
		stderr = self.__decode_output(self.stderr)
		return stdout, stderr, exit_status


	def start(self):
		"""Opens a SSH Client connection to the remote host."""

		self.__verbose__(
			f"SSHing into host `{self.hostname}`...",
			end=""
		)

		try:

			self.client.connect(
				hostname = self.ip or self.hostname,
				username = self.username,
				password = self.password,
				port = self.port,
				pkey = self.ssh_key,
				look_for_keys = self.look_for_keys,
				timeout = self.timeout,
				banner_timeout = self.timeout,
				auth_timeout = self.timeout
			)

			self.__verbose__("Connected!")

		except TimeoutError as error:
			self.__verbose__("Failed!")
			print(error)


	# def upload_file(self, local, remote=None):
		# """Upload a file using SFTP.

		# Args:
		# 	local (str):  Path to local file to upload.
		# 	remote (str):  Remote path to upload to.
		# """
	# 	if not self.active():
	# 		self.start()
	# 	self.sftp  = self.client.open_sftp()
	# 	if not remote:
	# 		remote = f"$HOME/{os.path.basename(local)}"
	# 	self.sftp.put(os.path.expanduser(local), remote)


	# def download_file(self, remote, local=None):
		# """Download a file using SFTP.

		# Args:
		# 	remote (str):  Remote path to file to download from.
		# 	local (str):  Path to local directory to save file too.
		# """
	# 	if not self.active():
	# 		self.start()
	# 	self.sftp  = self.client.open_sftp()
	# 	if not local:
	# 		local = os.path.expanduser(f"~/Downloads/{os.path.basename(remote)}")
	# 	self.sftp.get(remote, local)


	@__start_ssh
	def download(
		self, file: PathTypes | Iterable[PathTypes], local_path: PathTypes = "~/Downloads"):
		"""Download a file from remote server using SCP.

		Args:
			file (PathTypes | Iterable[PathTypes]):  File or files paths to download.
			local_path (str, optional):  Local path to download file(s) too.
				Defaults to "~/Downloads".

		Raises:
			FileExistsError:  If a local file of the same name already exists.
				(Otherwise it would be overwritten.)
		"""

		if isinstance(file, str):
			file = [file]

		for _file in file:

			local_file = f"{os.path.expanduser(local_path)}/{os.path.basename(_file)}"

			if os.path.exists(local_file):
				raise FileExistsError(f"[WARNING] A file with this name already exists:  {local_file}")

			with scp.SCPClient(self.client.get_transport(), progress=self.__scp_progress) as _scp:
				_scp.get(_file, local_file)
				self.__verbose__("\nDownload(s) complete!")


	@__start_ssh
	def upload(self, file: PathTypes | Iterable[PathTypes], remote_path: PathTypes = "."):
		"""Upload a file or files to a remote server using SCP.

		Args:
			file (PathTypes | Iterable[PathTypes]):  File or file paths to upload.
			remote_path (str, optional):  Remote path to upload file(s) into.
				Defaults to ".".

		Raises:
			FileExistsError: If the local file does not exist.
		"""

		local_file = f"{os.path.expanduser(file)}"

		if not os.path.exists(local_file):
			raise FileExistsError(f"[ERROR] File does not exist:  {local_file}")

		with scp.SCPClient(self.client.get_transport(), progress=self.__scp_progress) as _scp:
			_scp.put(local_file, remote_path=remote_path, recursive=True)
			self.__verbose__("\nUpload(s) complete!")


class SSHConfig(BaseModel):
	"""SSH Configuration Model"""
	username: str
	password: str
	port: int = 22
	ssh_key: str or paramiko.PKey = None  # parameter for paramiko.SSHClient().connect &
		# sshtunnel.SSHTunnelForwarder
	look_for_keys: bool = True  # parameter for paramiko.SSHClient().connect
	timeout: int = 10  # parameter for paramiko.SSHClient().connect & sshtunnel.SSHTunnelForwarder
	client: Optional[SSHClient | contextlib.nullcontext]

	class Config:
		arbitrary_types_allowed = True


class DatabaseConfig(BaseModel):
	"""Database Configuration Model"""
	port: int = 3306
	name: str = "jamfsoftware"
	username: str
	password: str
	timeout: int = 10  # parameter for mysql.connector.MySQLConnection


class JamfProAPI(BaseModel):
	"""Jamf Pro API Credentials Model"""
	username: str
	password: str
	url: str


class App_Server(BaseModel):
	"""JPS App Server Model"""
	hostname: str
	ip: str
	ssh: SSHConfig


class DB_Server(App_Server):
	"""JPS DB Server Model"""
	use_ssh: bool = True
	allow_agent: bool = False  # parameter for sshtunnel.SSHTunnelForwarder
	database: DatabaseConfig
	sql: Optional[MySQLClient | contextlib.nullcontext]

	class Config:
		arbitrary_types_allowed = True


class Instance(BaseModel):
	"""JPS Instance Model"""
	name: str
	api: JamfProAPI
	Primary: App_Server
	Secondary: Optional[list[App_Server]]
	Database: DB_Server


class Environment(BaseModel):
	"""Jamf Pro Environment"""
	Environments: list[Instance]


class TextFormat:
	"""Simple class that can be used to modified text.
	For example, when printing to console/terminal.
	"""
	purple = '\033[95m'
	cyan = '\033[96m'
	dark_cyan = '\033[36m'
	blue = '\033[94m'
	green = '\033[92m'
	yellow = '\033[93m'
	red = '\033[91m'
	bold = '\033[1m'
	underline = '\033[4m'
	end = '\033[0m'


class JamfProCTLError(Exception):
	"""Base Exception Class.

	Args:
		stdout (str):  stdout from the executed command.
		stderr (str):  stderr from the executed command.
		exit_status (int):  exit code from the executed command.
		supplemental_msg (str):  Info on what failed to be included with message.
	"""

	def __init__(self, stdout: str, stderr: str, exit_status: int, supplemental_msg: str = ""):
		self.stdout = stdout
		self.stderr = stderr
		self.exit_status = exit_status
		self.message = f"{TextFormat.red}{TextFormat.bold}[FAILED]{TextFormat.end} \
			{supplemental_msg}\nExit code:  {exit_status}\n{stdout = }\n{stderr =}"
		super().__init__(self.message)


class DatabaseBackupError(Exception):
	"""Raised when a database backup fails.

	Args:
		stdout (str):  stdout from the executed command.
		stderr (str):  stderr from the executed command.
		exit_status (int):  exit code from the executed command.
		supplemental_msg (str):  Info on what failed to be included with message.
	"""

	def __init__(
		self, stdout: str, stderr: str, exit_status: int, supplemental_msg: str = "Backup failed!"
	):
		self.stdout = stdout
		self.stderr = stderr
		self.exit_status = exit_status
		self.message = f"{supplemental_msg}\n\tExit code:  {exit_status}\n\t{stdout = }\n\t{stderr =}"
		super().__init__(self.message)


class JamfProCTL():
	"""A class module that sets up an object to interact with an Jamf Pro Server instance.

	Supports multi-server environments, SSH, and MySQL interactions.
		* Support for decrypting database contents is included.

	Helper methods to perform common tasks are also provided.

	A yaml formatted configuration file is required to load and utilize this module.  If one is not
	provided, it will look for the default file name ".jps_env.yaml" in the current users' home
	directory and then the current directory.
	"""

	def __init__(self, env: str, config_file: str = None, verbose:bool = True):
		self.env = env
		self.config_file = config_file
		self.verbose = verbose
		self.server = None

		# Load configuration
		self.config = self.load_config(self.env)

		# Database decryption related variables
		# There are hard-coded in the Jamf Pro software
		# (PasswordServiceImpl.class and PasswordServiceImpl$Encrypter.class)
		self.storage_key = "2M#84->)y^%2kGmN97ZLfhbL|-M:j?"
		self.salt = b"\xA9\x9B\xC8\x32\x56\x35\xE3\x03"
		self.iterations = 19
		self.session_key = None


	def __verbose__(self, message: str, end: str = "\n", file: io.TextIOWrapper = sys.stdout):
		"""Handles verbose messaging

		Args:
			message (str):  A message to be printed.
			end (str, optional):  A string that will be appended after the last value of `message`.
				Defaults to newline (i.e. `\\n`).
			file (file-like object (stream), optional):  Where the message will be sent.
				Defaults to the current sys.stdout.
		"""

		if self.verbose:
			print(
				f"{TextFormat.bold}[Verbose]{TextFormat.end} {message}",
				end = end,
				file = file
			)


	def load_config(self, env: str):
		"""Load configuration file and required secrets.

		Args:
			env (str):  Path to a configuration file in yaml format.

		Raises:
			FileNotFoundError: If the configuration file cannot be found.

		Returns:
			Instance:  An Instance of Jamf Pro Server environment.
		"""

		config = next(
			(
				config_file
				for config_file in (
					# self.config_file,
					os.path.join(os.path.expanduser("~"), ".jps_env.yaml"),
					os.path.join(os.path.abspath(os.curdir), ".jps_env.yaml"),
				)
				if os.path.exists(config_file)
			),
			None,
		)

		if not config:
			raise FileNotFoundError(f"The specified config file does not exist:  {config}")

		with open(config) as file:
			config = yaml.safe_load(file)

		# Validate configuration
		configuration = Environment(**config)

		for config_env in configuration.Environments:

			if re.match(env, config_env.name, re.IGNORECASE):
				self.get_servers(config_env)
				return config_env


	def get_servers(self, config: Instance):
		"""Parse configuration to set server attributes within module.

		Args:
			config (Instance):  The configuration of an instance
		"""

		def add_tunnel(server: App_Server | DB_Server):
			"""Helper method to add an SSHClient to each server object.
			Also adds a Database connection instance to database objects.

			Args:
				server (App_Server | DB_Server):  A server object

			Returns:
				(App_Server | DB_Server):  The modified server object
			"""

			server.ssh.client = SSHClient(server, verbose = self.verbose)
			return server


		for role, server in config:
			match role:

				case "Primary":
					self.primary: App_Server = add_tunnel(server)

				case "Secondary":
					self.secondary: list[App_Server] = []

					if not isinstance(server, list):
						server = [server]
					for _server in server:
						self.secondary.append(add_tunnel(_server))

				case "Database":

					self.database: DB_Server = add_tunnel(server)

					# Create database connection instance
					self.database.sql = MySQLClient(
						self.database,
						dictionary = True,
						verbose = self.verbose
					)


	def __which_server(func):
		"""Helper function to be used as a decorator that determines which
		server a methods should be executed against.

		Not to be called directly.

		Args:
			func (callable):  A function or other callable that will be executed.

		Returns:
			any:  Results of the passed function.
		"""

		@functools.wraps(func)
		def wrap(self, *args, **kwargs):
			"""Standard decorator function."""


			def match_server(server: str):
				"""Finds a server from the defined server attributes.

				Args:
					server str: A str matching a server object's hostname.

				Returns:
					(App_Server | DB_Server):  A server object.
				"""

				for jps in [ self.primary, self.database ] + self.secondary:
					if re.match(server, jps.hostname, re.IGNORECASE):
						return jps


			if "server" in kwargs:
				server = kwargs.get("server")
				self.server = server if isinstance(server, (App_Server, DB_Server)) \
					else match_server(server)

			elif not self.server:
				self.server = match_server(
					self.__prompt_for_input("Which server?", answer_example=""))

			return func(self, *args, **kwargs)


		return wrap


	def __check_results(self, stdout, stderr, exit_status, action):
		"""A helper function to check if a executed command was successful.

		Args:
			stdout (str):  stdout from an executed command.
			stderr (str):  stderr from an executed command.
			exit_status (int):  exit code from an executed command.
			action (str): A descriptive str of what was being attempted.

		Raises:
			JamfProCTLError: Base error if the command failed to successfully execute.
		"""

		if exit_status != 0:
			raise JamfProCTLError(stdout, stderr, exit_status, supplemental_msg=action)


	def open_sessions(self):
		"""Convenience function to identify which server object
		have open SSH and database connections.

		Returns:
			list[dict]:  [{"server": "open connection"}, ...]
		"""

		active_sessions = [
			{ server.ssh.client.hostname: server.ssh.client }
			for server in [self.primary, self.database] + self.secondary
			if server.ssh.client.active()
		]

		if self.database.sql.tunnel and self.database.sql.tunnel.is_active:
			active_sessions.append({
				self.database.hostname
				if self.database.ip == self.database.sql.tunnel.ssh_host
				else self.database.sql.tunnel.ssh_host: self.database.sql.tunnel._server_list[0]
			})

		if self.database.sql.db_connection and self.database.sql.db_connection.is_connected():
			active_sessions.append({self.database.sql.hostname: self.database.sql.db_connection})

		return active_sessions


	def close_sessions(self):
		"""Convenience function to close open SSH and database connections."""

		for jps in [self.primary, self.database] + self.secondary:
			# Close SSH Clients
			jps.ssh.client.close()

		if self.database.sql:
			# Close database connections
			self.database.sql.close()


	@__which_server
	def download(
		self,
		file: PathTypes | Iterable[PathTypes],
		server: Optional(str | App_Server | DB_Server) = None,
		local_path: PathTypes = "~/Downloads",
		**kwargs
	):
		"""Convenience function that maps to the server objects nested download method.

		Download a file from remote server using SCP.

		Args:
			file (PathTypes | Iterable[PathTypes]):  File or files paths to download.
			local_path (str, optional):  Local path to download file(s) too.
				Defaults to "~/Downloads".
			server (str | App_Server | DB_Server, optional):  Optionally provide a
				server to run function against.

		Raises:
			FileExistsError:  If a local file of the same name already exists.
				(Otherwise it would be overwritten.)
		"""

		return self.server.ssh.client.download(file=file, local_path=local_path)


	@__which_server
	def upload(
		self,
		file: PathTypes | Iterable[PathTypes],
		server: Optional(str | App_Server | DB_Server) = None,
		remote_path: PathTypes = ".",
		**kwargs
	):
		"""Convenience function that maps to the server objects nested upload method.

		Upload a file or files to a remote server using SCP.

		Args:
			file (PathTypes | Iterable[PathTypes]):  File or file paths to upload.
			remote_path (str, optional):  Remote path to upload file(s) into.
				Defaults to ".".

		Raises:
			FileExistsError: If the local file does not exist.
		"""

		return self.server.ssh.client.upload(file=file, remote_path=remote_path)


	@__which_server
	def get_logs(
		self,
		log_type: Literal("all", "Access", "ChangeManagement", "SoftwareServer") = "SoftwareServer",
		which: Literal("all", "latest") = "latest",
		server: Optional(str | App_Server | DB_Server) = None,
		local_path: PathTypes = "~/Downloads",
		**kwargs
	):
		"""Convenience function to download Jamf Pro logs.

		Args:
			log_type (str, optional):  The log type to download.
				Options are:  "all", "Access", "ChangeManagement", "SoftwareServer"
				Defaults to "SoftwareServer".
			which (str, optional): Download either the "latest" or "all"
				logs of the log_type requested.
			 	Defaults to "latest".
			local_path (str, optional):  Local path to download file(s) too.
				Defaults to "~/Downloads".
			server (str | App_Server | DB_Server, optional):  Optionally provide a
				server to run function against.

		Raises:
			FileExistsError:  If a local file of the same name already exists.
				(Otherwise it would be overwritten.)
		"""

		def list_logs(filter: str = None):

			all_logs = self.execute(
				cmd="ls /usr/local/jss/logs/", server=self.server, close_ssh=False)

			if filter:
				return [ log for log in all_logs[0].split("\n") if re.search(filter, log) ]

			return all_logs


		if log_type == "all":
			_download_logs = ( list_logs() if which == "all" else list_logs(filter=".*[.]log$") )

		else:
			match log_type:
				case "Access":
					filter_for_type = "JSSAccess"
				case "ChangeManagement":
					filter_for_type = "JAMFChangeManagement"
				case "SoftwareServer":
					filter_for_type = "JAMFSoftwareServer"

			_download_logs = list_logs(filter=f"{filter_for_type}.*") if which == "all" else [f"{filter_for_type}.log"]

		download_logs = [ f"/usr/local/jss/logs/{log}" for log in _download_logs ]
		self.download(file=download_logs, local_path=local_path)


	@__which_server
	def execute(
		self,
		cmd: str,
		server: Optional(str | App_Server | DB_Server) = None,
		close_ssh: bool = True
	):
		"""Convenience function that maps to the server objects nested execute_cmd method.

		Args:
			cmd (str):  Command to be ran on remote host.
			close_ssh (bool, optional):  Whether or not to close the SSH, if opened,
				after executing command.
				Defaults to True.
			server (str | App_Server | DB_Server, optional):  Override the current
				server object to execute function against.
				Defaults to None.

		Returns:
			tuple(stdout, stderr, exit_status):  The results of the executed command.
		"""

		stdout, stderr, exit_status = self.server.ssh.client.execute_cmd(cmd)

		# if self.use_ssh and close_ssh:
		# 	self.server.tunnel.close()

		return stdout, stderr, exit_status


	@__which_server
	def start(self, server: Optional(str | App_Server | DB_Server) = None, close_ssh: bool = True):
		"""Convenience function that starts the Jamf Pro Server Application.

		Args:
			close_ssh (bool, optional):  Whether or not to close the SSH, if opened,
				after executing command.
				Defaults to True.
			server (str | App_Server | DB_Server, optional):  Override the current
				server object to execute function against.
				Defaults to None.
		"""
		self.execute(
			cmd="sudo /usr/local/bin/jamf-pro server start", server=server, close_ssh=close_ssh)


	@__which_server
	def stop(self, server: Optional(str | App_Server | DB_Server) = None, close_ssh: bool = True):
		"""Convenience function that stops the Jamf Pro Server Application.

		Args:
			close_ssh (bool, optional):  Whether or not to close the SSH, if opened,
				after executing command.
				Defaults to True.
			server (str | App_Server | DB_Server, optional):  Override the current
				server object to execute function against.
				Defaults to None.
		"""

		self.__verbose__("Stopping Jamf Pro...")
		self.execute(
			cmd="sudo /usr/local/bin/jamf-pro server stop", server=server, close_ssh=close_ssh)


	@__which_server
	def restart(
		self, server: Optional(str | App_Server | DB_Server) = None, close_ssh: bool = True):
		"""Convenience function that restarts the Jamf Pro Server Application.

		Args:
			close_ssh (bool, optional):  Whether or not to close the SSH, if opened,
				after executing command.
				Defaults to True.
			server (str | App_Server | DB_Server, optional):  Override the current
				server object to execute function against.
				Defaults to None.
		"""

		self.execute(
			cmd="sudo /usr/local/bin/jamf-pro server restart", server=server, close_ssh=close_ssh)


	def db_backup(self, close_ssh: bool = True):
		"""Convenience function that performs a backup the Jamf Pro database.

		Args:
			close_ssh (bool, optional):  Whether or not to close the SSH, if opened,
				after executing command.
				Defaults to True.
		"""

		self.__verbose__("Backing up the Jamf Pro Database...")
		stdout, stderr, exit_status = self.execute(
			cmd = "sudo /usr/local/bin/jamf-pro database backup",
			close_ssh = close_ssh,
			server = self.database
		)

		if exit_status != 0:
			raise DatabaseBackupError(stdout, stderr, exit_status)

		backup_location = re.search(r"(Database backup file: .+[.]sql[.]gz)", stdout)
		self.__verbose__("Backup successful!")
		print(f"{backup_location[0]}")
		return stdout, stderr, exit_status


	@__which_server
	def install_jamf_pro(
		self,
		server: Optional(str | App_Server | DB_Server) = None,
		installer: str = "jamf-pro-installer-linux-*",
		close_ssh: bool = True
	):
		"""Convenience function that installs an previously uploaded Jamf Pro Server installer.

		Notes:
			* Expects the compressed installer is at the root of the SSH username's home directory.
			* The compressed installer will be decompressed and installed

		Args:
			close_ssh (bool, optional):  Whether or not to close the SSH, if opened,
				after executing command.
				Defaults to True.
			server (str | App_Server | DB_Server, optional):  Override the current
				server object to execute function against.
				Defaults to None.
		"""

		self.__verbose__(f"Installing the Jamf Pro update on:  `{server}`")

		stdout, stderr, exit_status = self.execute(
			cmd = "[[ -d ./update ]] && rm -rf ./update && mkdir ./update",
			server = server,
			close_ssh = False
		)
		self.__check_results(stdout, stderr, exit_status, action="Staging directory")

		stdout, stderr, exit_status = self.execute(
			cmd = f"mv ./{installer} ./update",
			server = server,
			close_ssh = False
		)
		self.__check_results(stdout, stderr, exit_status, action="Moving the installer")

		stdout, stderr, exit_status = self.execute(
			cmd = f"unzip ./update/{installer} -d ./update/",
			server = server,
			close_ssh = False
		)
		self.__check_results(stdout, stderr, exit_status, action="Extracting the archive")

		stdout, stderr, exit_status = self.execute(
			cmd = "sudo sh ./update/jamfproinstaller.run --quiet -- -d -y",
			server = server,
			close_ssh = close_ssh
		)
		self.__check_results(stdout, stderr, exit_status, action="Installing the update")


	def update(
		self,
		installer: PathTypes | Iterable[PathTypes] = None,
		prompt_to_continue: bool = True,
		skip_upload: bool = False
	):
		"""Convenience function that handles upgrading an entire Jamf Pro Server instance.

		Args:
			installer (str):  Path to a Jamf Pro installer to upload and install.
			prompt_to_continue (bool, optional):  Whether to prompt to continue after each step.
				Defaults to True.
		"""

		if not installer:
			installer = "jamf-pro-installer-linux-*"

		if not skip_upload:
			self.__verbose__("Uploading the installer...")

			for server in [self.primary] + self.secondary:
				self.upload(installer, server=server)

			installer = os.path.basename(installer)

		if prompt_to_continue and not self.__prompt_for_input("Stop the JPS instance?"):
			return

		for server in [self.primary] + self.secondary:
			self.stop(close_ssh=False, server=server)

		if prompt_to_continue and not self.__prompt_for_input("Backup Jamf Pro Database?"):
			return

		self.db_backup(close_ssh=True)

		while not self.__prompt_for_input("Have snapshots been taken for virtual servers?"):
			pass

		if prompt_to_continue and not self.__prompt_for_input("Update Primary JPS?"):
			return
		self.install_jamf_pro(installer=installer, close_ssh=False, server=self.primary)

		if self.secondary:
			if prompt_to_continue and not self.__prompt_for_input("Update Secondary JPS(s)?"):
				return

			for server in self.secondary:
				self.install_jamf_pro(installer=installer, close_ssh=True, server=server)

		self.close_sessions()


	def __get_session_key(func):
		"""Gets the encrypted encryption key from the database to decrypt it.

		Not to be called directly.

		Modified from initial reverse engineering and code created by:
			dmaasland @ https://github.com/dmaasland/jamf_decrypt

		Args:
			func (callable):  A function or other callable that will be executed.

		Raises:
			mysql.connector.errors.InterfaceError: If a MySQL Instance is not configured.
			TypeError: If the database is using an unsupported encryption method.

		Returns:
			str:  The decryption key.
		"""

		@functools.wraps(func)
		def wrap(self, *args, **kwargs):
			"""Standard decorator function."""

			if not self.database.sql:
				raise mysql.connector.errors.InterfaceError(
					"A database connection has not been established")

			if not self.session_key:

				# Get encrypted session key from database
				results, _ = self.database.sql.query(
					"SELECT \
						FROM_BASE64(encryption_key) AS encryption_key, \
						encryption_type \
					FROM encryption_key \
					;"
				)

				encryption_key = results[0].get("encryption_key")
				encryption_type = results[0].get("encryption_type")

				# Check if it's AES
				if encryption_type != 1:
					raise TypeError("Unsupported encryption method")

				# Decrypt the session key
				self.session_key = self.decrypt(encryption_key, self.storage_key)

			result = func(self, *args, **kwargs)

			# if "close_ssh" in kwargs and kwargs["close_ssh"]:
			# 	print("SSH Tunnel should be closed!")
				# self.server.tunnel.close()

			return result
		return wrap


	def decrypt(self, encrypted_value: str, decryption_key: Optional[str] = None):
		"""Decrypt the passed encrypted text with the passed decryption key.

		Modified from initial reverse engineering and code created by:
			dmaasland @ https://github.com/dmaasland/jamf_decrypt

		Args:
			encrypted_value (str):  Encrypted string.
			decryption_key (str, optional):  Decryption string.
				Defaults to None.

		Returns:
			str:  The decrypted string from the encrypted string.
		"""

		if not decryption_key:
			decryption_key = (self.session_key).decode("utf-8")

		# Generate key and IV
		generator = jasypt4py.generator.PKCS12ParameterGenerator(SHA256)
		key, iv = generator.generate_derived_parameters(decryption_key, self.salt, self.iterations)

		# Do actual decryption
		cipher = AES.new(key, AES.MODE_CBC, iv)

		try:
			plain_text = Padding.unpad(cipher.decrypt(encrypted_value), AES.block_size)
		except IndexError:
			plain_text = cipher.decrypt(encrypted_value)

		# Return decrypted data
		return plain_text


	@__get_session_key
	def query(
		self,
		table: str,
		record_filter: Optional[dict] = "",
		decrypt: bool = False,
		out_as_table: bool = False
	):
		"""Get a table's contents, optionally:
			* filtering for a record,
			* decrypt encrypted fields,
			* return as a dict or "pretty print" to stdout

		Args:
			table (str):  A table in the Jamf Pro database.
			record_filter (dict, optional):  A dict value to filter a table by.  The key
				in the table will be used as the column filter and the dict value will be
				used as the column value.
				Defaults to "" (or no filter value).
			out_as_table (bool):  The output format of the results.
				Defaults to "False".

		Returns:
			Return type is dependant on the `out` argument; options are:
				dict:  Table contents in a a dictionary format with encrypted columns decrypted.
				table:  If `out_as_table == True`, table contents will be printed to stdout with
					encrypted columns decrypted.
		"""

		if record_filter:
			key = list(record_filter)[0]
			value = record_filter.get(key)
			record_filter = f" where {key} = {value}"

		results, meta_data = self.database.sql.query(f"SELECT * FROM {table}{record_filter};")

		if decrypt and \
			any(column.endswith("_encrypted") for column in meta_data.get("column_names")):
			self.__verbose__(f"Found encrypted data in table '{table}', decrypting...")

			encrypted_results = results.copy()
			results = []

			for record in encrypted_results:

				new_record = {}

				for key, value in record.items():

					if value and key.endswith("_encrypted"):
						key = key.replace('_encrypted', '_decrypted')

						decrypted_contents = self.decrypt(base64.b64decode(value))

						if key.find("key") != -1:
							decrypted_contents = base64.b64encode(decrypted_contents)

						decrypted_contents = (decrypted_contents).decode()
						value = decrypted_contents

					new_record[key] = value
				results.append(new_record)

		return self.__format_as_table(results) if out_as_table else results


	@__get_session_key
	def dump_encrypted_tables(self, out: os.path = os.path.curdir):
		"""Dump only tables that contain encrypted values to html files.

		Modified from initial reverse engineering and code created by:
			dmaasland @ https://github.com/dmaasland/jamf_decrypt

		Args:
			out (os.path, optional):  A directory where results will be saved.
				Defaults to os.path.curdir.
		"""

		tables, _ = self.database.sql.query(
			f"SELECT DISTINCT TABLE_NAME \
				FROM INFORMATION_SCHEMA.COLUMNS \
				WHERE \
					TABLE_SCHEMA = '{self.database.database.name}' \
					AND COLUMN_NAME LIKE '%_encrypted%' \
			;",
			close_ssh = False
		)

		try:

			out = os.path.abspath(out)
			if not os.path.exists(os.path.abspath(out)):
				os.makedirs(os.path.abspath(out))

			for table in tables:

				table = table.get("TABLE_NAME")

				table_contents, query_details = self.database.sql.query(
					f"SELECT * FROM {table};", close_ssh = False)

				if query_details.get("rowcount") == 0:
					# Table doesn't have any records.
					continue

				html_filename = f"{out}/{os.path.basename(table)}.html"

				with open(f"{html_filename}", "w") as html_file:

					html_file.write(
						"<!DOCTYPE html>\n<html>\n\t<head>\n\t\t<meta charset=\"UTF-8\">"
						f"{self.__init_css()}\n\t</head>\n\t<body>\n\t\t<table>\n\t\t\t<tbody>"
						"\n\t\t\t\t<tr>\n"
					)

					for column in query_details.get("column_names"):

						if column.endswith("_encrypted"):
							column = column.replace('_encrypted', '_decrypted')

						html_file.write(f"\t\t\t\t\t<th>{column}</th>\n")

					html_file.write("\t\t\t\t</tr>\n")

					for row in table_contents:
						html_file.write("\t\t\t\t<tr>\n")

						for column, value in row.items():

							if column.endswith("_encrypted"):

								if value:
									decrypted_contents = self.decrypt(base64.b64decode(value))

									if column.find("key") != -1:
										decrypted_contents = base64.b64encode(decrypted_contents)

									html_file.write(
										f"\t\t\t\t\t<td>{(decrypted_contents).decode()}</td>\n")

								else:
									html_file.write(f"\t\t\t\t\t<td></td>\n")

							else:
								try:
									html_file.write(f"\t\t\t\t\t<td>{str(value)}</td>\n")
								except UnicodeDecodeError:
									html_file.write(f"\t\t\t\t\t<td>{value.encode('hex')}</td>\n")

						html_file.write("\t\t\t\t</tr>\n")

					html_file.write("\t\t\t</tbody>\n\t\t</table>\n\t</body>\n</html>")

		except Exception as error:
			raise(error)

		# finally:
		# 	self.ssh_tunnel.close()


	def __prompt_for_input(self, question: str, answer_example: str = "[Yes|No]"):
		"""Ask a question via input() and determine the value of the answer.

		Args:
			question (str):  A string that is written to stdout.
			answer_example (str):  The answer example that will be presented to
				the user along with the question.

		Returns:
			True or false based on the users' answer
		"""

		print(f"{question} {answer_example} ", end="")
		while True:

			try:

				answer = input()

				if answer_example == "[Yes|No]":

					if re.match(r"[Yy]([Ee][Ss])?", answer):
						return True
					if re.match(r"[Nn]([Oo])?", answer):
						return False

				return answer

			except ValueError:

				print('Please respond with [yes|y] or [no|n]: ', end="")


	def __init_css(self):
		"""Simply returns a CSS style block for an HTML page."""

		return """
		<style type="text/css">
			tbody th {
				border: 1px solid #000;
			}
			tbody td {
				border: 1px solid #ababab;
				border-spacing: 0px;
				padding: 4px;
				border-collapse: collapse;
				overflow: hidden;
				text-overflow: ellipsis;
				max-width: 200px;
			}
			body {
				font-family: verdana;
			}
			table {
				font-size: 13px;
				border-collapse: collapse;
				width: 100%;
			}
			tbody tr:nth-child(odd) td {
				background-color: #eee;
			}
			tbody tr:hover td {
				background-color: lightblue;
			}
		</style>"""


	def __format_as_table(self, results: list):
		"""Takes the the results of a SQL Query and outputs it in the format
			of a text based table, similar to that of a cli tool to stdout.

		Borrowed and modified from source:  https://stackoverflow.com/a/69181604

		Args:
			results (list):  The results of a SQL Query in a dictionary format.

		Returns:
			str:  The str formatted into a table.
		"""

		if not len(results):
			return []

		# Add col headers length to widths
		max_widths = {key: len(key) for key in results[0].keys()}

		# Add max content lengths to widths
		for row in results:
			for key in row.keys():
				if len(str(row[key])) > max_widths[key]:
					max_widths[key] = len(str(row[key]))

		widths = [max_widths[key] for key in results[0].keys()]
		pipe = "|"
		separator = "+"

		for w in widths:
			pipe += f" %-{w}.{w}s |"
			separator += "-" * w + "--+"

		visual_table = f"{separator}\n" + pipe % tuple(results[0].keys()) + f"\n{separator}\n"

		for row in results:
			visual_table += pipe % tuple(row.values()) + "\n"

		visual_table += f"{separator}\n"

		print(visual_table)
