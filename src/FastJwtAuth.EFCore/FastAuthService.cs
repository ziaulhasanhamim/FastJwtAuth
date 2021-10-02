using FastJwtAuth.Core.Services;
using FastJwtAuth.EFCore.Entities;

namespace FastJwtAuth
{
    public interface IFastAuthService : IFastAuthService<FastUser, FastRefreshToken>
    {

    }

    public class FastAuthService : FastAuthService<FastUser, FastRefreshToken>, IFastAuthService
    {
        public FastAuthService(IFastUserStore<FastUser, FastRefreshToken> userStore, FastAuthOptions authOptions) : base(userStore, authOptions)
        {
        }
    }
}
