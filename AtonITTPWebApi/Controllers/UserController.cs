using AtonITTPWebApi.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.AspNetCore.Mvc;

namespace AtonITTPWebApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UsersController : ControllerBase
    {
        private static List<User> _users = new List<User>
        {
            new User
            {
                Login = "admin",
                Password = "adminPassword",
                Name = "user_1 (admin)",
                Gender = 1,
                Birthday = null,
                Admin = true,
                CreatedBy = "System",
            }
        };

        private User authenticate(string login, string password)
        {
            return _users.FirstOrDefault(u => u.Login == login && u.Password == password && u.RevokedOn == null);
        }

        private bool isAdmin(User user)
        {
            return user != null && user.Admin;
        }

        [HttpPost]
        public IActionResult createUser(User user, [FromHeader] string login, [FromHeader] string password)
        {
            var adminUser = authenticate(login, password);
            if (adminUser == null || !isAdmin(adminUser))
                return Unauthorized("Только админы могут создать нового пользователя.");

            if (_users.Any(u => u.Login == user.Login))
                return BadRequest("Пользователь с таким логином уже существует.");

            user.CreatedBy = adminUser.Login;
            user.CreatedOn = DateTime.UtcNow;
            _users.Add(user);

            return Ok(user);
        }

        [HttpPut("update-info/{loginToUpdate}")]
        public IActionResult updateUserInfo(string loginToUpdate, User updatedInfo, [FromHeader] string login, [FromHeader] string password)
        {
            var requestingUser = authenticate(login, password);
            var userToUpdate = _users.FirstOrDefault(u => u.Login == loginToUpdate && u.RevokedOn == null);

            if (requestingUser == null || userToUpdate == null)
                return NotFound("Пользователь не найден или не авторизован.");

            if (!isAdmin(requestingUser) && requestingUser.Login != loginToUpdate)
                return Unauthorized("Вы можете обновлять только свою информацию.");

            userToUpdate.Name = updatedInfo.Name;
            userToUpdate.Gender = updatedInfo.Gender;
            userToUpdate.Birthday = updatedInfo.Birthday;
            userToUpdate.ModifiedBy = requestingUser.Login;
            userToUpdate.ModifiedOn = DateTime.UtcNow;

            return Ok(userToUpdate);
        }

        [HttpPut("update-password/{loginToUpdate}")]
        public IActionResult updateUserPassword(string loginToUpdate, [FromBody] string newPassword, [FromHeader] string login, [FromHeader] string password)
        {
            var requestingUser = authenticate(login, password);
            var userToUpdate = _users.FirstOrDefault(u => u.Login == loginToUpdate && u.RevokedOn == null);

            if (requestingUser == null || userToUpdate == null)
                return NotFound("Пользователь не найден или не авторизован.");

            if (!isAdmin(requestingUser) && requestingUser.Login != loginToUpdate)
                return Unauthorized("Вы можете обновить только свой пароль.");

            userToUpdate.Password = newPassword;
            userToUpdate.ModifiedBy = requestingUser.Login;
            userToUpdate.ModifiedOn = DateTime.UtcNow;

            return Ok(userToUpdate);
        }

        [HttpPut("update-login/{loginToUpdate}")]
        public IActionResult updateUserLogin(string loginToUpdate, [FromBody] string newLogin, [FromHeader] string login, [FromHeader] string password)
        {
            var requestingUser = authenticate(login, password);
            var userToUpdate = _users.FirstOrDefault(u => u.Login == loginToUpdate && u.RevokedOn == null);

            if (requestingUser == null || userToUpdate == null)
                return NotFound("Пользователь не найден или не авторизован.");

            if (!isAdmin(requestingUser) && requestingUser.Login != loginToUpdate)
                return Unauthorized("Вы можете обновить только свой логин.");

            if (_users.Any(u => u.Login == newLogin))
                return BadRequest("Пользователь с таким логином уже существует.");

            userToUpdate.Login = newLogin;
            userToUpdate.ModifiedBy = requestingUser.Login;
            userToUpdate.ModifiedOn = DateTime.UtcNow;

            return Ok(userToUpdate);
        }

        [HttpGet("active-users")]
        public IActionResult getActiveUsers([FromHeader] string login, [FromHeader] string password)
        {
            var adminUser = authenticate(login, password);
            if (adminUser == null || !isAdmin(adminUser))
                return Unauthorized("Только админ может просматривать список активных пользователей.");

            var activeUsers = _users.Where(u => u.RevokedOn == null).OrderBy(u => u.CreatedOn).ToList();
            return Ok(activeUsers);
        }

        [HttpGet("{login}")]
        public IActionResult getUserByLogin(string login, [FromHeader] string requestLogin, [FromHeader] string requestPassword)
        {
            var adminUser = authenticate(requestLogin, requestPassword);
            if (adminUser == null || !isAdmin(adminUser))
                return Unauthorized("Только админ может просматривать данные пользователей.");

            var user = _users.FirstOrDefault(u => u.Login == login);
            if (user == null)
                return NotFound("Пользователь не найден.");

            return Ok(new { user.Name, user.Gender, user.Birthday, IsActive = user.RevokedOn == null });
        }

        [HttpGet("self")]
        public IActionResult getUserByCredentials([FromHeader] string login, [FromHeader] string password)
        {
            var user = authenticate(login, password);
            if (user == null)
                return Unauthorized("Неверные данные или пользователь не существует.");

            return Ok(new { user.Name, user.Gender, user.Birthday, IsActive = user.RevokedOn == null });
        }

        [HttpGet("older-than/{age}")]
        public IActionResult getUsersOlderThan(int age, [FromHeader] string login, [FromHeader] string password)
        {
            var adminUser = authenticate(login, password);
            if (adminUser == null || !isAdmin(adminUser))
                return Unauthorized("Только админы могут просматривать список пользователей старше определенного возраста.");

            var now = DateTime.UtcNow;
            var usersOlderThan = _users.Where(u => u.Birthday.HasValue && (now.Year - u.Birthday.Value.Year) >= age).ToList();
            return Ok(usersOlderThan);
        }

        [HttpDelete("{login}")]
        public IActionResult deleteUser(string login, [FromBody] bool isSoftDelete, [FromHeader] string requestLogin, [FromHeader] string requestPassword)
        {
            var adminUser = authenticate(requestLogin, requestPassword);
            if (adminUser == null || !isAdmin(adminUser))
                return Unauthorized("Только админы могут удалять пользователей.");

            var user = _users.FirstOrDefault(u => u.Login == login);
            if (user == null)
                return NotFound("Пользователь не найден.");

            if (isSoftDelete)
            {
                user.RevokedOn = DateTime.UtcNow;
                user.RevokedBy = adminUser.Login;
            }
            else
            {
                _users.Remove(user);
            }

            return Ok();
        }

        [HttpPut("restore/{login}")]
        public IActionResult restoreUser(string login, [FromHeader] string requestLogin, [FromHeader] string requestPassword)
        {
            var adminUser = authenticate(requestLogin, requestPassword);
            if (adminUser == null || !isAdmin(adminUser))
                return Unauthorized("Только админы могут восстанавливать пользователей.");

            var user = _users.FirstOrDefault(u => u.Login == login && u.RevokedOn != null);
            if (user == null)
                return NotFound("Пользователь не найден или активаен.");

            user.RevokedOn = null;
            user.RevokedBy = null;

            return Ok(user);
        }
    }
}
