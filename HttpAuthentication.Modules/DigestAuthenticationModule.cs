using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace HttpAuthentication.Modules
{
    public class DigestAuthenticationModule : IHttpModule
    {
        private const string Digest = "Digest";

        public void Init(HttpApplication context)
        {
            throw new NotImplementedException();
        }

        public void Dispose()
        {
            throw new NotImplementedException();
        }
    }
}
