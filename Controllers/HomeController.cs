﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace WebApplication4.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }

        [Authorize]
        public ActionResult About()
        {
            ViewBag.Message = $"Your application description page. You are authenticated as {User.Identity.Name}";

            return View();
        }

        [Authorize]
        public ActionResult Contact()
        {
            ViewBag.Message = $"Your contact page. You are authenticated as {User.Identity.Name}";

            return View();
        }
    }
}