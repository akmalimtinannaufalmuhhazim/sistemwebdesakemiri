const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const db = require("./config/database");
const { analyzeComplaint } = require("./services/ai-service");

const app = express();
const PORT = process.env.PORT || 3000;

// =========================================================================
// SISTEM SELF-HEALING (ANTI CRASH ENGINE)
// Mencegah server mati mendadak jika ada error atau bug logika
// =========================================================================
process.on("uncaughtException", (err) => {
  console.error("[CRITICAL ERROR] Web dicegah dari kematian total:", err);
});
process.on("unhandledRejection", (reason, promise) => {
  console.error("[PROMISE ERROR] Web dicegah dari kematian total:", reason);
});

// Config Upload & Hapus File Fisik
const storage = multer.diskStorage({
  destination: "./public/uploads/",
  filename: (req, file, cb) =>
    cb(
      null,
      "kemiri-" + Date.now() + path.extname(file.originalname).toLowerCase(),
    ),
});

// =========================================================================
// PERBAIKAN EXTREME: Limit Upload Foto Dinaikkan Menjadi 1 GB
// 1 GB = 1024 MB * 1024 KB * 1024 Bytes
// =========================================================================
const upload = multer({
  storage: storage,
  limits: { fileSize: 1024 * 1024 * 1024 }, // 1 GB
});

const hapusFotoLama = (img) => {
  if (img && img.startsWith("/uploads/")) {
    const p = path.join(__dirname, "public", img);
    if (fs.existsSync(p)) fs.unlinkSync(p);
  }
};

// Batas limit JSON juga DIBONGKAR sampai 1 GB (1024mb) untuk menampung Base64 super besar
app.use(express.urlencoded({ extended: true, limit: "1024mb" }));
app.use(express.json({ limit: "1024mb" }));
app.use(express.static("public"));
app.set("view engine", "ejs");

// Keamanan Session Cookie Ditingkatkan
app.use(
  session({
    secret: "SuperSecretCyberKemiri2026!@#",
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 1000 * 60 * 60 * 2,
      httpOnly: true, // Mencegah pencurian cookie via XSS
      sameSite: "lax",
    },
  }),
);

const requireAuth = (req, res, next) => {
  if (!req.session.userId) return res.redirect("/login");
  next();
};

const simpanGambarBase64 = (base64String) => {
  if (!base64String) return null;
  const base64Data = base64String.replace(/^data:image\/\w+;base64,/, "");
  const filename = "crop-" + Date.now() + ".jpg";
  const filepath = path.join(__dirname, "public/uploads", filename);
  fs.writeFileSync(filepath, base64Data, "base64");
  return "/uploads/" + filename;
};

// --- ROUTES PUBLIC ---
app.get("/", (req, res) => {
  res.render("index", {
    profile: db.prepare("SELECT * FROM profile WHERE id = 1").get(),
    news: db.prepare("SELECT * FROM news ORDER BY id DESC LIMIT 5").all(),
    destinations: db.prepare("SELECT * FROM destinations").all(),
    officials: db.prepare("SELECT * FROM officials").all(),
    potensi: db.prepare("SELECT * FROM potensi").all(),
    umkm: db.prepare("SELECT * FROM umkm").all(),
  });
});

app.post("/kirim-laporan", (req, res) => {
  const { nama, kontak, kategori, pesan } = req.body;
  const ticketId = "KMR-" + Date.now().toString().slice(-4);
  db.prepare(
    "INSERT INTO reports (ticket_id, sender_name, sender_contact, category, message, ai_response) VALUES (?, ?, ?, ?, ?, ?)",
  ).run(
    ticketId,
    nama,
    kontak,
    kategori,
    pesan,
    analyzeComplaint(kategori, pesan),
  );
  res.json({ status: "success", ticket: ticketId });
});

// =========================================================================
// SISTEM KEAMANAN CYBER: ANTI BRUTE-FORCE LOGIN
// =========================================================================
const loginAttempts = {};
const MAX_ATTEMPTS = 5;
const LOCKOUT_TIME = 15 * 60 * 1000; // 15 Menit

app.get("/login", (req, res) => res.render("login", { error: null }));
app.post("/login", async (req, res) => {
  const ip = req.ip || req.connection.remoteAddress;

  // Cek apakah Hacker sedang diblokir
  if (loginAttempts[ip] && loginAttempts[ip].count >= MAX_ATTEMPTS) {
    if (Date.now() - loginAttempts[ip].time < LOCKOUT_TIME) {
      return res.render("login", {
        error:
          "Keamanan Cyber: Terdeteksi percobaan peretasan. Silakan coba 15 Menit lagi.",
      });
    } else {
      loginAttempts[ip].count = 0; // Buka blokir setelah 15 menit
    }
  }

  const user = db
    .prepare("SELECT * FROM users WHERE username = ?")
    .get(req.body.username);

  if (user && (await bcrypt.compare(req.body.password, user.password))) {
    req.session.userId = user.id;
    delete loginAttempts[ip]; // Reset keamanan jika sukses login
    res.redirect("/admin");
  } else {
    // Catat kegagalan
    if (!loginAttempts[ip]) loginAttempts[ip] = { count: 0, time: Date.now() };
    loginAttempts[ip].count += 1;
    loginAttempts[ip].time = Date.now();

    res.render("login", {
      error: `Username/Password salah! Peringatan keamanan: ${MAX_ATTEMPTS - loginAttempts[ip].count} percobaan tersisa.`,
    });
  }
});
app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/login");
});

// --- DASHBOARD ADMIN ---
app.get("/admin", requireAuth, (req, res) => {
  res.render("dashboard", {
    profile: db.prepare("SELECT * FROM profile WHERE id = 1").get(),
    reports: db.prepare("SELECT * FROM reports ORDER BY id DESC").all(),
    news: db.prepare("SELECT * FROM news ORDER BY id DESC").all(),
    destinations: db.prepare("SELECT * FROM destinations").all(),
    officials: db.prepare("SELECT * FROM officials").all(),
    potensi: db.prepare("SELECT * FROM potensi").all(),
    umkm: db.prepare("SELECT * FROM umkm").all(),
  });
});

// --- CRUD API ---
// PROFILE
app.post(
  "/admin/profile/update",
  requireAuth,
  upload.single("image"),
  (req, res) => {
    const {
      description,
      history,
      hotline,
      stat_penduduk,
      stat_mdpl,
      stat_suhu,
      stat_dusun,
      founded_year,
      profile_heading,
    } = req.body;

    if (req.file) {
      hapusFotoLama(
        db.prepare("SELECT image FROM profile WHERE id=1").get().image,
      );
      db.prepare(
        "UPDATE profile SET description=?, history=?, hotline=?, stat_penduduk=?, stat_mdpl=?, stat_suhu=?, stat_dusun=?, founded_year=?, profile_heading=?, image=? WHERE id=1",
      ).run(
        description,
        history,
        hotline,
        stat_penduduk,
        stat_mdpl,
        stat_suhu,
        stat_dusun,
        founded_year,
        profile_heading,
        "/uploads/" + req.file.filename,
      );
    } else {
      db.prepare(
        "UPDATE profile SET description=?, history=?, hotline=?, stat_penduduk=?, stat_mdpl=?, stat_suhu=?, stat_dusun=?, founded_year=?, profile_heading=? WHERE id=1",
      ).run(
        description,
        history,
        hotline,
        stat_penduduk,
        stat_mdpl,
        stat_suhu,
        stat_dusun,
        founded_year,
        profile_heading,
      );
    }
    res.redirect("/admin");
  },
);

// NEWS
app.post("/admin/news/add", requireAuth, upload.single("image"), (req, res) => {
  db.prepare("INSERT INTO news (title, content, image) VALUES (?, ?, ?)").run(
    req.body.title,
    req.body.content,
    req.file ? "/uploads/" + req.file.filename : "",
  );
  res.redirect("/admin");
});
app.post(
  "/admin/news/edit",
  requireAuth,
  upload.single("image"),
  (req, res) => {
    if (req.file) {
      hapusFotoLama(
        db.prepare("SELECT image FROM news WHERE id=?").get(req.body.id).image,
      );
      db.prepare("UPDATE news SET title=?, content=?, image=? WHERE id=?").run(
        req.body.title,
        req.body.content,
        "/uploads/" + req.file.filename,
        req.body.id,
      );
    } else {
      db.prepare("UPDATE news SET title=?, content=? WHERE id=?").run(
        req.body.title,
        req.body.content,
        req.body.id,
      );
    }
    res.redirect("/admin");
  },
);
app.get("/admin/news/delete/:id", requireAuth, (req, res) => {
  hapusFotoLama(
    db.prepare("SELECT image FROM news WHERE id=?").get(req.params.id).image,
  );
  db.prepare("DELETE FROM news WHERE id=?").run(req.params.id);
  res.redirect("/admin");
});

// DESTINATIONS
app.post(
  "/admin/destinations/add",
  requireAuth,
  upload.single("image"),
  (req, res) => {
    db.prepare(
      "INSERT INTO destinations (name, description, map_link, image) VALUES (?, ?, ?, ?)",
    ).run(
      req.body.name,
      req.body.description,
      req.body.map_link,
      req.file ? "/uploads/" + req.file.filename : "",
    );
    res.redirect("/admin");
  },
);
app.post(
  "/admin/destinations/edit",
  requireAuth,
  upload.single("image"),
  (req, res) => {
    if (req.file) {
      hapusFotoLama(
        db.prepare("SELECT image FROM destinations WHERE id=?").get(req.body.id)
          .image,
      );
      db.prepare(
        "UPDATE destinations SET name=?, description=?, map_link=?, image=? WHERE id=?",
      ).run(
        req.body.name,
        req.body.description,
        req.body.map_link,
        "/uploads/" + req.file.filename,
        req.body.id,
      );
    } else {
      db.prepare(
        "UPDATE destinations SET name=?, description=?, map_link=? WHERE id=?",
      ).run(
        req.body.name,
        req.body.description,
        req.body.map_link,
        req.body.id,
      );
    }
    res.redirect("/admin");
  },
);
app.get("/admin/destinations/delete/:id", requireAuth, (req, res) => {
  hapusFotoLama(
    db.prepare("SELECT image FROM destinations WHERE id=?").get(req.params.id)
      .image,
  );
  db.prepare("DELETE FROM destinations WHERE id=?").run(req.params.id);
  res.redirect("/admin");
});

// POTENSI
app.post(
  "/admin/potensi/add",
  requireAuth,
  upload.single("image"),
  (req, res) => {
    db.prepare(
      "INSERT INTO potensi (title, description, image) VALUES (?, ?, ?)",
    ).run(
      req.body.title,
      req.body.description,
      req.file ? "/uploads/" + req.file.filename : "",
    );
    res.redirect("/admin");
  },
);
app.post(
  "/admin/potensi/edit",
  requireAuth,
  upload.single("image"),
  (req, res) => {
    if (req.file) {
      hapusFotoLama(
        db.prepare("SELECT image FROM potensi WHERE id=?").get(req.body.id)
          .image,
      );
      db.prepare(
        "UPDATE potensi SET title=?, description=?, image=? WHERE id=?",
      ).run(
        req.body.title,
        req.body.description,
        "/uploads/" + req.file.filename,
        req.body.id,
      );
    } else {
      db.prepare("UPDATE potensi SET title=?, description=? WHERE id=?").run(
        req.body.title,
        req.body.description,
        req.body.id,
      );
    }
    res.redirect("/admin");
  },
);
app.get("/admin/potensi/delete/:id", requireAuth, (req, res) => {
  hapusFotoLama(
    db.prepare("SELECT image FROM potensi WHERE id=?").get(req.params.id).image,
  );
  db.prepare("DELETE FROM potensi WHERE id=?").run(req.params.id);
  res.redirect("/admin");
});

// UMKM
app.post("/admin/umkm/add", requireAuth, upload.single("image"), (req, res) => {
  db.prepare(
    "INSERT INTO umkm (name, description, price, location, whatsapp, image) VALUES (?, ?, ?, ?, ?, ?)",
  ).run(
    req.body.name,
    req.body.description,
    req.body.price,
    req.body.location,
    req.body.whatsapp,
    req.file ? "/uploads/" + req.file.filename : "",
  );
  res.redirect("/admin");
});
app.post(
  "/admin/umkm/edit",
  requireAuth,
  upload.single("image"),
  (req, res) => {
    if (req.file) {
      hapusFotoLama(
        db.prepare("SELECT image FROM umkm WHERE id=?").get(req.body.id).image,
      );
      db.prepare(
        "UPDATE umkm SET name=?, description=?, price=?, location=?, whatsapp=?, image=? WHERE id=?",
      ).run(
        req.body.name,
        req.body.description,
        req.body.price,
        req.body.location,
        req.body.whatsapp,
        "/uploads/" + req.file.filename,
        req.body.id,
      );
    } else {
      db.prepare(
        "UPDATE umkm SET name=?, description=?, price=?, location=?, whatsapp=? WHERE id=?",
      ).run(
        req.body.name,
        req.body.description,
        req.body.price,
        req.body.location,
        req.body.whatsapp,
        req.body.id,
      );
    }
    res.redirect("/admin");
  },
);
app.get("/admin/umkm/delete/:id", requireAuth, (req, res) => {
  hapusFotoLama(
    db.prepare("SELECT image FROM umkm WHERE id=?").get(req.params.id).image,
  );
  db.prepare("DELETE FROM umkm WHERE id=?").run(req.params.id);
  res.redirect("/admin");
});

// OFFICIALS (CROPPER)
app.post(
  "/admin/officials/add",
  requireAuth,
  upload.single("image"),
  (req, res) => {
    let finalImagePath = "";
    if (req.body.cropped_image) {
      finalImagePath = simpanGambarBase64(req.body.cropped_image);
    } else if (req.file) {
      finalImagePath = "/uploads/" + req.file.filename;
    }
    db.prepare(
      "INSERT INTO officials (name, position, image) VALUES (?, ?, ?)",
    ).run(req.body.name, req.body.position, finalImagePath);
    res.redirect("/admin");
  },
);
app.post(
  "/admin/officials/edit",
  requireAuth,
  upload.single("image"),
  (req, res) => {
    if (req.body.cropped_image) {
      hapusFotoLama(
        db.prepare("SELECT image FROM officials WHERE id=?").get(req.body.id)
          .image,
      );
      const finalImagePath = simpanGambarBase64(req.body.cropped_image);
      db.prepare(
        "UPDATE officials SET name=?, position=?, image=? WHERE id=?",
      ).run(req.body.name, req.body.position, finalImagePath, req.body.id);
    } else if (req.file) {
      hapusFotoLama(
        db.prepare("SELECT image FROM officials WHERE id=?").get(req.body.id)
          .image,
      );
      db.prepare(
        "UPDATE officials SET name=?, position=?, image=? WHERE id=?",
      ).run(
        req.body.name,
        req.body.position,
        "/uploads/" + req.file.filename,
        req.body.id,
      );
    } else {
      db.prepare("UPDATE officials SET name=?, position=? WHERE id=?").run(
        req.body.name,
        req.body.position,
        req.body.id,
      );
    }
    res.redirect("/admin");
  },
);
app.get("/admin/officials/delete/:id", requireAuth, (req, res) => {
  hapusFotoLama(
    db.prepare("SELECT image FROM officials WHERE id=?").get(req.params.id)
      .image,
  );
  db.prepare("DELETE FROM officials WHERE id=?").run(req.params.id);
  res.redirect("/admin");
});

// ERROR HANDLER GLOBAL (Mencegah web blank putih jika error)
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === "LIMIT_FILE_SIZE") {
      return res
        .status(400)
        .send(
          `<h2>Gagal Upload!</h2><p>Ukuran foto terlalu besar (Maksimal 1 GB). Silakan kembali dan coba lagi.</p><br><a href="/admin">Kembali ke Admin</a>`,
        );
    }
  }
  console.error("Express Error Catch:", err.stack);
  res
    .status(500)
    .send(
      "Terjadi kendala pada sistem. Tim IT sedang memulihkannya. Silakan kembali beberapa saat lagi.",
    );
});

app.listen(PORT, () => {
  console.log(`🚀 Web Desa Kemiri berjalan di: http://localhost:${PORT}`);
});
