using System;
using System.Diagnostics;
using System.Text;
using System.Web;
using System.Net.Http.Headers;

// HTTP Authentication: Basic and Digest Access Authentication
// https://tools.ietf.org/html/rfc2617
// https://tools.ietf.org/html/rfc2069

// https://docs.microsoft.com/en-us/aspnet/web-api/overview/security/basic-authentication
// https://blogs.msdn.microsoft.com/daniem/2013/02/27/digest-authentication-in-system-net-classes-dont-fully-comply-with-rfc2617/

namespace HttpAuthentication.Modules
{
    public class BasicAuthenticationModule : IHttpModule
    {
        private const string Basic = "Basic";
        private const string EnvName = "HTTP_AUTHENTICATION_MODULE";

        private string _authType;
        private string _realm;
        private string _userName;
        private string _password;
        private bool _isInit = false;

        public void Init(HttpApplication context)
        {
            context.BeginRequest += OnBeginRequest;
            var env = Environment.GetEnvironmentVariable(EnvName);
            var args = env?.Split('|');

            if (args != null && args.Length == 4 && args[0].Equals(Basic, StringComparison.OrdinalIgnoreCase))
            {
                _authType = Basic;
                _realm = args[1];
                _userName = args[2];
                _password = args[3];
                _isInit = true;
            }
            else
                Trace.TraceError($"{EnvName} parse error: {env}");
        }

        private bool CheckPassword(string username, string password)
        {
            return username == _userName && password == _password;
        }

        private void AuthenticateUser(string credentials)
        {
            try
            {
                var encoding = Encoding.GetEncoding("iso-8859-1");
                credentials = encoding.GetString(Convert.FromBase64String(credentials));

                var separator = credentials.IndexOf(':');
                var name = credentials.Substring(0, separator);
                var password = credentials.Substring(separator + 1);

                if (!CheckPassword(name, password))
                {
                    WwwAuthenticateRequestEnd();
                }
            }
            catch (FormatException)
            {
                WwwAuthenticateRequestEnd();
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void OnBeginRequest(object sender, EventArgs e)
        {
            if(!_isInit) return;

            var request = HttpContext.Current.Request;
            var authHeader = request.Headers["Authorization"];
            if (authHeader != null)
            {
                var authHeaderVal = AuthenticationHeaderValue.Parse(authHeader);

                // RFC 2617 sec 1.2, "scheme" name is case-insensitive
                if (authHeaderVal.Scheme.Equals(Basic, StringComparison.OrdinalIgnoreCase) &&
                    authHeaderVal.Parameter != null)
                {
                    AuthenticateUser(authHeaderVal.Parameter);
                }
            }
            else
            {
                WwwAuthenticateRequestEnd();
            }
        }

        private void WwwAuthenticateRequestEnd()
        {
            HttpContext.Current.Response.StatusCode = 401;
            HttpContext.Current.Response.Headers.Add("WWW-Authenticate", $"{_authType} realm=\"{_realm}\"");
            HttpContext.Current.Response.End();
        }

        public void Dispose()
        {
        }
    }
}
