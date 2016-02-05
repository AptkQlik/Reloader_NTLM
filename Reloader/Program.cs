using System;
using System.Collections.Concurrent;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Permissions;
using System.Security.Principal;
using System.Threading.Tasks;
using Qlik.Engine;
using Qlik.Engine.Communication.IO;

namespace Reloader
{
	/// <summary>
	/// This example is written to illustrate how to avoid consuming license tokens and how to use other credentials than the logged on user. 
	/// It is important to NOT let the Location be disposed or instanciated more than once as each Location consumes a token. 
	/// This example is a console exe that reloads apps using only one license token, a FileSystemWather is used to trigger app reloads.
	/// When a file is created with the name of an app it will start a reload task on that app.
	/// 
	/// I order to configure and run this example you will need to specify :
	/// * reload folder (see _path)
	/// * address (see _serverAddress) to a Qlik Sense instance.
	/// * username (see _user)
	/// * domain (see _domain)
	/// * password (see _password)
	/// 
	/// It assumes that the proxy is configured to accept the computer running this example and that "Allow http" is enabled if accessing with "http://" or "ws://".
	/// It assumes that the user is in the the "ContentAdmin" role (reload previleges).
	/// 
	/// This example does not cover cancelelation of the task or a ongoing reload.
	/// </summary>
	class Program
	{
		private static string _path = @"c:\reload"; // Set the path to a watcher folder
		private static string _serverAddress = "https://qlikserver.mydomain.com";
		private static string _user = "myUser";
		private static string _domain = "myDomain";
		private static string _password = "myPassword";

		private static int _pollcount = 0;
		private static ILocation _qlikSenseServer = null;
		private static ConcurrentQueue<string> ReloadTasks = new ConcurrentQueue<string>();

		[PermissionSet(SecurityAction.Demand, Name = "FullTrust")]
		public static void Main(string[] args)
		{
			try
			{
				//http://stackoverflow.com/questions/9021414/dynamic-impersonation-in-asp-net
				if (Impersonation.impersonateValidUser(_user, _domain, _password))
				{
					_qlikSenseServer = Qlik.Engine.Location.FromUri(new Uri(_serverAddress));
					_qlikSenseServer.AsNtlmUserViaProxy();

					Console.WriteLine("Press any key to quit."); // Wait for the user to quit the program.

					SetupFileWatcherAndEnqueueExistingFiles();

					bool doWork = true;
					while (doWork)
					{
						string app;
						if (ReloadTasks.TryDequeue(out app))
						{
							if (app == null) // Check if there is any app to reload.
								continue;

							var appId = _qlikSenseServer.AppWithNameOrDefault(app, noVersionCheck: true);
							if (appId != null)
							{
								Task task = ReloadApplicationTask(appId); // No wait or cancelation implementet
							}
							File.Delete(app); // The file has been processed we can now delete it.
						}
						doWork = DoSomeIdleWorkAndKeepTheSessionAlive();
					} // end while
				}
			}
			catch (Exception e)
			{
				var errMsg = e.InnerException != null ? " inner exception: " + e.InnerException.Message : string.Empty;
				Console.WriteLine("Unhandled exception " + e.Message + errMsg);
			}
		}

		private static bool DoSomeIdleWorkAndKeepTheSessionAlive()
		{
			if (Console.KeyAvailable)
				return false; // Somebody pressed a key stop reloading

			Console.Write(".");
			System.Threading.Thread.Sleep(10000); // Give the qlik engine some time to reload.

			_pollcount++;
			if (_pollcount >= 5)
			{
				// Keep the connection alive so that we do not need to handle disconnects.
				Console.WriteLine(_qlikSenseServer.Hub(noVersionCheck: true).ProductVersion());
				_pollcount = 0;
			}
			return true;
		}

		private static void SetupFileWatcherAndEnqueueExistingFiles()
		{
			foreach (var file in Directory.GetFiles(_path)) // Enque all existing files....
				ReloadTasks.Enqueue(file);

			// Create a new FileSystemWatcher and set its properties.
			var watcher = new FileSystemWatcher
			{
				Path = _path,
				NotifyFilter =
					NotifyFilters.LastAccess | NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.DirectoryName,
				Filter = "*.*"
			};

			watcher.Created += new FileSystemEventHandler(OnCreated); // Add event handlers.
			watcher.EnableRaisingEvents = true; // Begin watching.
		}

		private static void OnCreated(object source, FileSystemEventArgs e)
		{
			Console.WriteLine("New reload request Enqueued - App: " + e.Name + " " + e.ChangeType);
			ReloadTasks.Enqueue(e.Name);
		}

		private static async Task ReloadApplicationTask(IAppIdentifier appIdentifier)
		{
			using (IApp app = await _qlikSenseServer.AppAsync(appIdentifier, noVersionCheck:true))
			{
				Console.WriteLine("App with name {0} opened", appIdentifier.AppName);
				AsyncHandle reloadHandle = new AsyncHandle("reloadTask");

				// By setting mode parameter on reload you can affect the behaviour check the help for more information.
				// http://help.qlik.com/sense/2.1/en-US/apis/net%20sdk/html/M_Qlik_Engine_App_DoReload.htm
				// During the reload task you can cancel the reload by calling app.Session.Hub.CancelReload() you should also need to cancel the "reloadTask"
				try
				{
					var reloadTask = app.DoReloadAsync(reloadHandle, OnReloaded);

					bool doWork = true;
					while (doWork)
					{
						var progress = await app.Session.Hub.GetProgressAsync(reloadHandle);
						Console.WriteLine("Progress: " + progress.TransientProgress + " Finished : " + progress.Finished);
						if (progress.Finished)
							doWork = false;

						System.Threading.Thread.Sleep(1000); // Give the qlik engine time to work before we check the progress again.
					}
					await app.DoSaveAsync();
					Console.WriteLine("App with name {0} saved and last reloaded {1}", appIdentifier.AppName, (await app.GetAppLayoutAsync()).LastReloadTime);
				}
				catch (TimeoutException e)
				{
					// We got a timeout exception from the SDK, handle this should be handled. In this example will just cancel the reload in the engine and igonre it.
					app.Session.Hub.CancelReload();
				}
			}
		}

		private static bool OnReloaded(Response response)
		{
			Console.WriteLine("App reloaded - Result " + response.ToString());
			return true;
		}
	}

	public class Impersonation
	{
		public static int LOGON32_LOGON_INTERACTIVE = 2;
		public static int LOGON32_PROVIDER_DEFAULT = 0;

		[DllImport("advapi32.dll")]
		public static extern int LogonUserA(string lpxzUsername, string lpzDomain, string lpzPassword, int dwLogonType, int dwLogonProvider, ref IntPtr phToken);
		[DllImport("advapi32.dll")]
		public static extern int DuplicateToken(IntPtr ExistingTokenHandle, int ImpersonationLevel, ref IntPtr DuplicateTokenHandle);
		[DllImport("advapi32.dll")]
		public static extern long RevertToSelf();

		[DllImport("Kernel32.dll")]
		public static extern long CloseHandle(IntPtr handle);

		public static WindowsImpersonationContext impersonationContext;

		public static bool impersonateValidUser(string userName, string domain, string password)
		{
			WindowsIdentity tempWindowsIdentity;
			IntPtr token = IntPtr.Zero;
			IntPtr tokenDuplicate = IntPtr.Zero;
			bool ValidUser = false;

			if (RevertToSelf() != 0)
			{
				if (LogonUserA(userName, domain, password, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, ref token) != 0)
				{
					if (DuplicateToken(token, 2, ref tokenDuplicate) != 0)
					{
						tempWindowsIdentity = new WindowsIdentity(tokenDuplicate);
						impersonationContext = tempWindowsIdentity.Impersonate();
						if (impersonationContext != null)
						{
							ValidUser = true;
						}
					}
				}
			}

			if (!tokenDuplicate.Equals(IntPtr.Zero))
			{
				CloseHandle(tokenDuplicate);
			}
			if (!token.Equals(IntPtr.Zero))
			{
				CloseHandle(token);
			}
			return ValidUser;

		}

		public static void undoImpersonation()
		{
			try
			{
				impersonationContext.Undo();
			}
			catch
			{
			}
		}
	}
}
