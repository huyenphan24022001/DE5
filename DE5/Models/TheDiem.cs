//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated from a template.
//
//     Manual changes to this file may cause unexpected behavior in your application.
//     Manual changes to this file will be overwritten if the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace DE5.Models
{
    using System;
    using System.Collections.Generic;
    
    public partial class TheDiem
    {
        public int ID { get; set; }
        public string LoaiThe { get; set; }
        public string TenThe { get; set; }
        public Nullable<int> CanDuoi { get; set; }
        public Nullable<int> CanTren { get; set; }
        public Nullable<bool> IsDelete { get; set; }
    }
}