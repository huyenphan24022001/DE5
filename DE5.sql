USE [DE5]
GO
/****** Object:  Table [dbo].[KhachHang]    Script Date: 7/29/2024 2:22:12 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[KhachHang](
	[ID] [int] IDENTITY(1,1) NOT NULL,
	[HoLot] [nvarchar](255) NOT NULL,
	[Ten] [nvarchar](255) NULL,
	[TaiKhoan] [nvarchar](255) NULL,
	[NgaySinh] [datetime] NULL,
	[DiaChi] [nvarchar](255) NULL,
	[NgayThamGia] [datetime] NULL,
	[Diem] [int] NULL,
	[IsDelete] [bit] NULL,
PRIMARY KEY CLUSTERED 
(
	[ID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[TheDiem]    Script Date: 7/29/2024 2:22:12 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[TheDiem](
	[ID] [int] IDENTITY(1,1) NOT NULL,
	[LoaiThe] [nvarchar](255) NOT NULL,
	[TenThe] [nvarchar](255) NULL,
	[CanDuoi] [int] NULL,
	[CanTren] [int] NULL,
	[IsDelete] [bit] NULL,
PRIMARY KEY CLUSTERED 
(
	[ID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Token]    Script Date: 7/29/2024 2:22:12 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Token](
	[ID] [int] IDENTITY(1,1) NOT NULL,
	[Users_ID] [int] NULL,
	[access_token] [nvarchar](255) NULL,
	[refresh_token] [nvarchar](255) NULL,
PRIMARY KEY CLUSTERED 
(
	[ID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Users]    Script Date: 7/29/2024 2:22:12 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Users](
	[ID] [int] IDENTITY(1,1) NOT NULL,
	[UserName] [nvarchar](255) NOT NULL,
	[Pass] [nvarchar](255) NULL,
	[Role] [int] NULL,
PRIMARY KEY CLUSTERED 
(
	[ID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
SET IDENTITY_INSERT [dbo].[KhachHang] ON 

INSERT [dbo].[KhachHang] ([ID], [HoLot], [Ten], [TaiKhoan], [NgaySinh], [DiaChi], [NgayThamGia], [Diem], [IsDelete]) VALUES (1, N'Phan', N'Huyền test', N'huyen@gmail.com', CAST(N'2024-06-12T00:00:00.000' AS DateTime), N'Thanh Bình', CAST(N'2024-06-16T15:42:54.787' AS DateTime), 55, 0)
INSERT [dbo].[KhachHang] ([ID], [HoLot], [Ten], [TaiKhoan], [NgaySinh], [DiaChi], [NgayThamGia], [Diem], [IsDelete]) VALUES (3, N'Phan', N'test', N'test@gmail.com', CAST(N'2024-06-17T00:00:00.000' AS DateTime), N'Thanh Bình', CAST(N'2024-06-16T15:45:26.147' AS DateTime), 0, 0)
SET IDENTITY_INSERT [dbo].[KhachHang] OFF
GO
SET IDENTITY_INSERT [dbo].[TheDiem] ON 

INSERT [dbo].[TheDiem] ([ID], [LoaiThe], [TenThe], [CanDuoi], [CanTren], [IsDelete]) VALUES (1, N'D', N'Nhôm', 0, 10, 0)
INSERT [dbo].[TheDiem] ([ID], [LoaiThe], [TenThe], [CanDuoi], [CanTren], [IsDelete]) VALUES (2, N'C', N'Đồng', 10, 50, 0)
INSERT [dbo].[TheDiem] ([ID], [LoaiThe], [TenThe], [CanDuoi], [CanTren], [IsDelete]) VALUES (3, N'B', N'Bạc', 50, 200, 0)
SET IDENTITY_INSERT [dbo].[TheDiem] OFF
GO
SET IDENTITY_INSERT [dbo].[Users] ON 

INSERT [dbo].[Users] ([ID], [UserName], [Pass], [Role]) VALUES (1, N'admin', N'f52EmOY2EqOlO+TvezMgDgWOo+sI249P1hzRKVcu1gE=', 1)
SET IDENTITY_INSERT [dbo].[Users] OFF
GO
ALTER TABLE [dbo].[Token]  WITH CHECK ADD FOREIGN KEY([Users_ID])
REFERENCES [dbo].[Users] ([ID])
GO
