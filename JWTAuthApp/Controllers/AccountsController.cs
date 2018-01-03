using System;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using System.Web.Http;
using System.Web.Http.Routing;
using JWTAuthApp.Models;
using Microsoft.AspNet.Identity; 


namespace JWTAuthApp.Controllers
{
    [RoutePrefix("api/accounts")]
    public class AccountsController : BaseApiController
    {
        [Authorize]
        [Route("users")]
        public IHttpActionResult GetUsers()
        {
            var user = User.Identity.GetUserName();
            return Ok(this.AppUserManager.Users.ToList().Select(u => this.TheModelFactory.Create(u)));
        }

        [Route("user/{id:guid}", Name = "GetUserById")]
        public async Task<IHttpActionResult> GetUser(string id)
        {
            var user = await this.AppUserManager.FindByIdAsync(id);

            if (user != null)
            {
                return Ok(this.TheModelFactory.Create(user));
            }

            return NotFound();

        }

        [Authorize]
        [Route("user/{username}")]
        public async Task<IHttpActionResult> GetUserByName(string username)
        {
            var user = await this.AppUserManager.FindByNameAsync(username);

            if (user != null)
            {
                return Ok(this.TheModelFactory.Create(user));
            }

            return NotFound();

        }

        [AllowAnonymous]
        [Route("create")]
        public async Task<IHttpActionResult> CreateUser(CreateUserBindingModel createUserModel)
        {
            
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var user = new ApplicationUser()
            {
                UserName = createUserModel.Username,
                Email = createUserModel.Email,
                FirstName = createUserModel.FirstName,
                LastName = createUserModel.LastName,
                EmailConfirmed = true
            };

            IdentityResult addUserResult = await this.AppUserManager.CreateAsync(user, createUserModel.Password);

            if (!addUserResult.Succeeded)
            {
                return GetErrorResult(addUserResult);
            }

            Uri locationHeader = new Uri(Url.Link("GetUserById", new { id = user.Id }));

            return Created(locationHeader, TheModelFactory.Create(user));
        }


        [Authorize]
        [Route("ChangePassword")]
        public async Task<IHttpActionResult> ChangePassword(ChangePasswordBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            var use = User.Identity.GetUserName();
            IdentityResult result = await this.AppUserManager.ChangePasswordAsync(User.Identity.GetUserId(), model.OldPassword, model.NewPassword);

            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            return Ok("Changed");
        }

        [Route("RecoveryPassword")]
        [Authorize]
        [HttpPost]
        public async Task<IHttpActionResult> RecoveryPassword(SetPasswordBindingModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await this.AppUserManager.FindByNameAsync(model.userName);
                if (user == null)
                {
                    return BadRequest("User is not exist");
                }

                var code = await this.AppUserManager.GeneratePasswordResetTokenAsync(user.Id);

                var result = await this.AppUserManager.ResetPasswordAsync(user.Id, code, model.NewPassword);
                if (result.Succeeded)
                {
                    return Ok("Password reset Successfully");
                }
                foreach (string error in result.Errors)
                {
                    ModelState.AddModelError("Error", error);
                }
            }
            return BadRequest(ModelState);
        }

        [Route("ForgotPassword")]
        [AllowAnonymous]
        [HttpPost]
        public async Task<IHttpActionResult> ForgotPassword(ForgotPasswordModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await this.AppUserManager.FindByNameAsync(model.EmployeeId);
                if (user == null)
                {
                    return BadRequest("Sorry! Employee Id is not exist");
                }
                if (user.Email == null)
                {
                    return BadRequest("Sorry! You have no mail attach. Please contact admin to recover Password");
                }
                try
                {
                    var code = await this.AppUserManager.GeneratePasswordResetTokenAsync(user.Id);
                    code = WebUtility.UrlEncode(code);
                    UrlHelper urlHelper = new UrlHelper(this.Request);
                    var url = urlHelper.Request + "/#/ResetPassword?id=" + user.Id + "&code=" + code;

                    await this.AppUserManager.SendEmailAsync(user.Id, "Reset Password", "Please reset your password by clicking <a href=\"" + new Uri(url) + "\">here</a>");
                    return Ok("Please check your Email and recovery Password");
                }
                catch (Exception e)
                {
                    return BadRequest(e.ToString());
                }
            }

            return BadRequest("Employee Id is required");
        }

        [Route("ResetPassword")]
        [HttpPost]
        [AllowAnonymous]
        public async Task<IHttpActionResult> ResetPassword(ResetPasswordModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await this.AppUserManager.FindByNameAsync(model.Id);

                if (user == null)
                {
                    return BadRequest("User is not exists");
                }

                var code = await this.AppUserManager.GeneratePasswordResetTokenAsync(user.Id);
                var result = await this.AppUserManager.ResetPasswordAsync(user.Id, code, model.NewPassword);
                if (result.Succeeded)
                {
                    return Ok("Password Reset Successfully");

                }
                else
                {
                    BadRequest("Code or id is incorrect plz resend again");
                }
            }
            return BadRequest("Internal Server Problem");
        }

        [Authorize]
        [HttpDelete]
        [Route("user/{id:guid}")]
        public async Task<IHttpActionResult> DeleteUser(string id)
        {
            //Only SuperAdmin or Admin can delete users (Later when implement roles)

            var appUser = await this.AppUserManager.FindByIdAsync(id);

            if (appUser != null)
            {
                IdentityResult result = await this.AppUserManager.DeleteAsync(appUser);

                if (!result.Succeeded)
                {
                    return GetErrorResult(result);
                }
                var user = this.AppUserManager.Users.ToList().Select(u => this.TheModelFactory.Create(u));
                return Ok(user);

            }

            return NotFound();

        }

        [Authorize(Roles = "Admin")]
        [Route("user/{id:guid}/roles")]
        [HttpPut]
        public async Task<IHttpActionResult> AssignRolesToUser([FromUri] string id, [FromBody] string[] rolesToAssign)
        {

            var appUser = await this.AppUserManager.FindByIdAsync(id);

            if (appUser == null)
            {
                return NotFound();
            }

            var currentRoles = await this.AppUserManager.GetRolesAsync(appUser.Id);

            var rolesNotExists = rolesToAssign.Except(this.AppRoleManager.Roles.Select(x => x.Name)).ToArray();

            if (!rolesNotExists.Any())
            {

                ModelState.AddModelError("", string.Format("Roles '{0}' does not exixts in the system", string.Join(",", rolesNotExists)));
                return BadRequest(ModelState);
            }

            IdentityResult removeResult = null;
            foreach (var currentRole in currentRoles)
            {
                removeResult = await this.AppUserManager.RemoveFromRoleAsync(appUser.Id, currentRole);
            }
            

            if (removeResult != null && !removeResult.Succeeded)
            {
                ModelState.AddModelError("", "Failed to remove user roles");
                return BadRequest(ModelState);
            }
            IdentityResult addResult = null;
            foreach (string roles in rolesToAssign)
            {
                  addResult = await this.AppUserManager.AddToRoleAsync(appUser.Id, roles);
            }
            

            if (addResult != null && !addResult.Succeeded)
            {
                ModelState.AddModelError("", "Failed to add user roles");
                return BadRequest(ModelState);
            }

            return Ok();

        }
    }
}