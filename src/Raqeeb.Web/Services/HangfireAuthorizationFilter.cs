using Hangfire.Dashboard;
using Raqeeb.Domain.Constants;

namespace Raqeeb.Web.Services
{
    public class HangfireAuthorizationFilter : IDashboardAuthorizationFilter
    {
        public bool Authorize(DashboardContext context)
        {
            var httpContext = context.GetHttpContext();
            
            // Allow access only to authenticated users in Admin or User roles
            return httpContext.User.Identity?.IsAuthenticated == true &&
                   (httpContext.User.IsInRole(Roles.Admin) || httpContext.User.IsInRole(Roles.User));
        }
    }
}
