AC_PREREQ(2.59)

AC_INIT([gnome-epub-thumbnailer], [1.6], [hadess@hadess.net])

AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE(1.9 dist-xz no-dist-gzip check-news)

# Enable silent build when available (Automake 1.11)
m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])])

AC_PROG_CC
AC_PROG_MAKE_SET
AC_PROG_INSTALL
AC_PROG_SED
AM_PROG_CC_C_O

PKG_CHECK_MODULES(THUMBNAILER, gdk-pixbuf-2.0 gio-2.0 libarchive libxml-2.0)

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
