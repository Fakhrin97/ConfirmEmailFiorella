﻿using System.ComponentModel.DataAnnotations;

namespace Fiorello.Models
{
    public class ResetPasswordViewModel
    {
        public string Mail { get; set; }
        public string Token { get; set; }

        [DataType(DataType.Password)]
        public string Password { get; set; }

        [DataType(DataType.Password) , Compare(nameof(Password))]
        public string ConfirmPassword { get; set; }

    }
}
