﻿using FastJwtAuth.Core.Entities;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FastJwtAuth.EFCore.Entities
{
    [Index(nameof(Email))]
    public class FastUser : IFastUser<Guid>
    {
        [Key]
        public Guid Id { get; set; }

        [Required]
        public string? Email { get; set; }

        [Required]
        public string? PasswordHash { get; set; }

        [Required]
        public DateTime CreatedAt { get; set; }

        public DateTime? LastLogin { get; set; }
    }
}
