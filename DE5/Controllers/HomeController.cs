using DE5.Models;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data.Entity;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Web.Mvc;

namespace DE5.Controllers
{
    public class HomeController : Controller
    {
        DE5Entities db = new DE5Entities();
        public ActionResult Index()
        {
            //check token còn thời gian k
            bool check = checkToken();
            if (!check)
            {
                return RedirectToAction("Login");
            }
            List<KhachHang> list = db.KhachHangs.Where(n => n.IsDelete == false).OrderByDescending(n => n.Diem).ToList();
            return View(list);
        }
        public ActionResult The()
        {
            //check token còn thời gian k
            bool check = checkToken();
            if (!check)
            {
                return RedirectToAction("Login");
            }
            List<TheDiem> list = db.TheDiems.Where(n => n.IsDelete == false).ToList();
            return View(list);
        }

        public ActionResult Login()
        {
            return View();
        }
        public ActionResult LogOut()
        {
            Session["Login"] = null;
            return View("Login");
        }
        public bool checkToken()
        {
            var access_token = Session["access_token"];
            if (access_token == null)
            {
                //return RedirectToAction("Login");
                return false;
            }
            else
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.ASCII.GetBytes(Convert.ToString(ConfigurationManager.AppSettings["config:JwtKey"]));
                tokenHandler.ValidateToken(access_token.ToString(), new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ClockSkew = TimeSpan.Zero

                }, out SecurityToken validatedToken);

                // Corrected access to the validatedToken
                var jwtToken = (JwtSecurityToken)validatedToken;
                if (jwtToken.ValidTo < DateTime.UtcNow)
                {
                    return false;
                    //return RedirectToAction(Action);
                }


            }
            return true;
            //return RedirectToAction("Login");
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Register(FormCollection collection, User u)
        {
            string pass = u.Pass;
            string rePass = collection["RePassword"];
            if (!pass.Equals(rePass))
            {
                return RedirectToAction("Error", "Home", new { @MaError = "Mật khẩu không trùng khớp!" });

            }
            if (db.Users.SingleOrDefault(x => x.UserName.Equals(u.UserName)) != null)
            {

                return RedirectToAction("Error", "Home", new { @MaError = "Tên Username đã tồn tại!" });


            }
           
            string hashedPassword = HashPassword(pass, "12345!#aB");
            User user = new User()
            {
                UserName = u.UserName,
                Pass = hashedPassword,
                Role = 1,

            };
            db.Users.Add(user);
            db.SaveChanges();
            return RedirectToAction("Success", "Home", new { Success = "Tạo tài khoản thành công" });
        }
        public static string HashPassword(string password, string salt)
        {
            using (var sha256 = SHA256.Create())
            {
                var saltedPassword = password + salt;
                var passwordBytes = Encoding.UTF8.GetBytes(saltedPassword);
                var hashBytes = sha256.ComputeHash(passwordBytes);
                return Convert.ToBase64String(hashBytes);
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Login(Login user)
        {
            var securityKey = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(ConfigurationManager.AppSettings["config:JwtKey"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            string hashedPassword = HashPassword(user.Password, "12345!#aB");
            User u = db.Users.FirstOrDefault(x => x.UserName == user.UserName && x.Pass == hashedPassword && x.Role == 1); //pass: 12345


            if (u != null)
            {
                var claims = new[]
        { new Claim("ID", u.ID.ToString()),
                    new Claim("UserName", u.UserName),
                    new Claim("Role", u.Role.ToString())
                    // Add more claims if needed
                };

                var accessToken = new JwtSecurityToken(
                    claims: claims,
                    expires: DateTime.UtcNow.AddHours(1), // Token expires in 1 hour
                    signingCredentials: credentials
                );

                var refreshToken = new JwtSecurityToken(
                    claims: claims,
                    expires: DateTime.UtcNow.AddDays(7), // Token expires in 7day
                    signingCredentials: credentials
                );
                var access_token = new JwtSecurityTokenHandler().WriteToken(accessToken);
                var refresh_token = new JwtSecurityTokenHandler().WriteToken(refreshToken);
                Models.Token to = new Models.Token()
                {
                    Users_ID = u.ID,
                    access_token = access_token,
                    refresh_token = refresh_token,
                };
                db.Tokens.Add(to);
                db.SaveChanges();

                Session["access_token"] = access_token;
                //Session["refresh_token"] = refresh_token;
                Session["Login"] = true;
                return RedirectToAction("Index", "Home");
            }
            else
            {
                ModelState.AddModelError("", "Login data is incorrect!");
            }
            return View();
        }
        public ActionResult Create()
        {
            //check token còn thời gian k
            bool check = checkToken();
            if (!check)
            {
                return RedirectToAction("Login");
            }
            return View();
        }
        [HttpPost]
        public ActionResult Create(FormCollection collection, KhachHang kh)
        {

            //check token còn thời gian k
            bool check = checkToken();
            if (!check)
            {
                return RedirectToAction("Login");
            }
            try
            {

                    kh.IsDelete = false;
                    kh.NgayThamGia = DateTime.Now;
                    kh.Diem = 0;
                if (db.KhachHangs.SingleOrDefault(x => x.TaiKhoan.Equals(kh.TaiKhoan)) == null)
                {
                    db.KhachHangs.Add(kh);

                    db.SaveChanges();
                    return RedirectToAction("Success", "Home", new { Success = "Thêm thành công" });
                }

                return RedirectToAction("Error", "Home", new { MaError = "Trùng tên tài khoản" });


            }
            catch (Exception e)
            {
                return RedirectToAction("Error", "Home", new { MaError = e.Message });
            }
        }
        public ActionResult CreateThe()
        {
            //check token còn thời gian k
            bool check = checkToken();
            if (!check)
            {
                return RedirectToAction("Login");
            }
            return View();
        }
        [HttpPost]
        public ActionResult CreateThe(FormCollection collection, TheDiem the)
        {
            //check token còn thời gian k
            bool check = checkToken();
            if (!check)
            {
                return RedirectToAction("Login");
            }
            try
            {

                the.IsDelete = false;

                if (db.TheDiems.SingleOrDefault(x => x.LoaiThe.Equals(the.LoaiThe) || x.TenThe.Equals(the.TenThe)) == null)
                {
                    db.TheDiems.Add(the);

                    db.SaveChanges();
                    return RedirectToAction("Success", "Home", new { Success = "Thêm thành công" });
                }

                return RedirectToAction("Error", "Home", new { MaError = "Trùng tên thẻ hoặc loại thẻ" });


            }
            catch (Exception e)
            {
                return RedirectToAction("Error", "Home", new { MaError = e.Message });
            }
        }
        public ActionResult Error(string MaError)
        {
            ViewBag.Error = MaError;
            return View();
        }

        public ActionResult Success(string Success)
        {
            ViewBag.Success = Success;
            return View();
        }
        public ActionResult Details(int? id)
        {

            //check token còn thời gian k
            bool check = checkToken();
            if (!check)
            {
                return RedirectToAction("Login");
            }
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            KhachHang nen = db.KhachHangs.Find(id);
            var the = db.TheDiems.Where(n => n.IsDelete == false).ToList();
            foreach(var item in the)
            {
                if (item.CanDuoi <= nen.Diem && item.CanTren > nen.Diem)
                {
                    ViewBag.The = item.TenThe;
                }
            }
            if (nen == null)
            {
                return HttpNotFound();
            }
            return View(nen);
        }
        public ActionResult Delete(int id)
        {

            //check token còn thời gian k
            bool check = checkToken();
            if (!check)
            {
                return RedirectToAction("Login");
            }
            if (id == null)
            {
                return Json(new { mess = "fail" }, JsonRequestBehavior.AllowGet);
            }
            KhachHang nen = db.KhachHangs.Find(id);
            if (nen == null)
            {
                return Json(new { mess = "fail" }, JsonRequestBehavior.AllowGet);
            }
            nen.IsDelete = true;
            db.SaveChanges();
            return Json(new { mess = "success" }, JsonRequestBehavior.AllowGet);
        }
        public ActionResult DeleteThe(int id)
        {

            //check token còn thời gian k
            bool check = checkToken();
            if (!check)
            {
                return RedirectToAction("Login");
            }
            if (id == null)
            {
                return Json(new { mess = "fail" }, JsonRequestBehavior.AllowGet);
            }
            TheDiem nen = db.TheDiems.Find(id);
            if (nen == null)
            {
                return Json(new { mess = "fail" }, JsonRequestBehavior.AllowGet);
            }
            nen.IsDelete = true;
            db.SaveChanges();
            return Json(new { mess = "success" }, JsonRequestBehavior.AllowGet);
        }
        public ActionResult Edit(int id)
        {

            //check token còn thời gian k
            bool check = checkToken();
            if (!check)
            {
                return RedirectToAction("Login");
            }
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            KhachHang nen = db.KhachHangs.Find(id);
            if (nen == null)
            {
                return HttpNotFound();
            }
            return View(nen);
        }
        public ActionResult EditThe(int id)
        {

            //check token còn thời gian k
            bool check = checkToken();
            if (!check)
            {
                return RedirectToAction("Login");
            }
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            TheDiem nen = db.TheDiems.Find(id);
            if (nen == null)
            {
                return HttpNotFound();
            }
            return View(nen);
        }
        [HttpPost]
        public ActionResult Edit(KhachHang kh, FormCollection collection)
        {
            //check token còn thời gian k
            bool check1 = checkToken();
            if (!check1)
            {
                return RedirectToAction("Login");
            }
            try
            {
                if (kh.ID != null)
                {
                    KhachHang check = db.KhachHangs.SingleOrDefault(n => n.ID == kh.ID);
                    if (check == null) return RedirectToAction("Error", "Home", new { MaError = "Không tìm thấy" });

                    check.IsDelete = false;
                    check.HoLot = kh.HoLot;
                    check.Ten = kh.Ten;
                    check.TaiKhoan = kh.TaiKhoan;
                    check.DiaChi = kh.DiaChi;
                    check.Diem = kh.Diem;
                    if (kh.NgaySinh != null)
                    {
                        check.NgaySinh = kh.NgaySinh;
                    }
                    db.Entry(check).State = EntityState.Modified;
                    db.SaveChanges();
                }

                return RedirectToAction("Success", "Home", new { Success = "Sửa thành công" });
            }
            catch (Exception e)
            {
                return RedirectToAction("Error", "Home", new { MaError = e.Message });
            }

        }
        [HttpPost]
        public ActionResult EditThe(TheDiem t, FormCollection collection)
        {
            //check token còn thời gian k
            bool check1 = checkToken();
            if (!check1)
            {
                return RedirectToAction("Login");
            }
            try
            {
                if (t.ID != null)
                {
                    TheDiem check = db.TheDiems.SingleOrDefault(n => n.ID == t.ID);
                    if (check == null) return RedirectToAction("Error", "Home", new { MaError = "Không tìm thấy" });

                    check.IsDelete = false;
                    check.LoaiThe = t.LoaiThe;
                    check.TenThe = t.TenThe;
                    check.CanTren = t.CanTren;
                    check.CanDuoi = t.CanDuoi;

                    db.Entry(check).State = EntityState.Modified;
                    db.SaveChanges();
                }

                return RedirectToAction("Success", "Home", new { Success = "Sửa thành công" });
            }
            catch (Exception e)
            {
                return RedirectToAction("Error", "Home", new { MaError = e.Message });
            }

        }
        public ActionResult TichDiem(int ID)
        {
            //check token còn thời gian k
            bool check = checkToken();
            if (!check)
            {
                return RedirectToAction("Login");
            }
            if (ID == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            KhachHang nen = db.KhachHangs.Find(ID);
            if (nen == null)
            {
                return HttpNotFound();
            }
            ViewBag.ID = ID;
            return View(nen);
        }
        [HttpPost]
        public ActionResult TichDiem( FormCollection collection)
        {
            //check token còn thời gian k
            bool check = checkToken();
            if (!check)
            {
                return RedirectToAction("Login");
            }
            try
            {
                int ID = Int32.Parse(collection["ID"]);
                int tien = Int32.Parse(collection["SoTien"]);
                int sodiem = tien / 1000;
                if (ID == null)
                {
                    return RedirectToAction("Error", "Home", new { MaError = "ID == null" });
                }
                KhachHang nen = db.KhachHangs.Find(ID);
                if (nen == null)
                {
                    return RedirectToAction("Error", "Home", new { MaError = "KH == null" });
                }
                nen.Diem += sodiem;
                db.SaveChanges();
                return RedirectToAction("Success", "Home", new { Success = "Sửa thành công" });
            }
            catch (Exception e)
            {
                return RedirectToAction("Error", "Home", new { MaError = e.Message });
            }

        }
    }
}