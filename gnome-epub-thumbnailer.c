/*
 * Copyright (C) 2013 Bastien Nocera <hadess@hadess.net>
 *
 * Authors: Bastien Nocera <hadess@hadess.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */

#include <string.h>
#include <glib.h>
#include <gio/gio.h>
#include <gdk-pixbuf/gdk-pixbuf.h>
#include <archive.h>
#include <archive_entry.h>

static int output_size = 64;
static gboolean g_fatal_warnings = FALSE;
static char **filenames = NULL;

static const GOptionEntry entries[] = {
	{ "size", 's', 0, G_OPTION_ARG_INT, &output_size, "Size of the thumbnail in pixels", NULL },
	{"g-fatal-warnings", 0, 0, G_OPTION_ARG_NONE, &g_fatal_warnings, "Make all warnings fatal", NULL},
	{ G_OPTION_REMAINING, '\0', 0, G_OPTION_ARG_FILENAME_ARRAY, &filenames, NULL, "[FILE...]" },
	{ NULL }
};

static char *
get_cover_path_from_metafile (const char *metafile,
			      gsize       length)
{
	//FIXME implement
	//
	//This means, finding the cover in the metafile, OR
	//finding the OPF root file in the metafile, and parsing that to find the cover image
	return NULL;
}

static int
regex_matches (gconstpointer a,
	       gconstpointer b)
{
	const char *path = a;
	GRegex *regex = (GRegex *) b;

	if (g_regex_match (regex, a, 0, NULL))
		return 0;
	return -1;
}

static char *
file_get_zipped_contents (const char   *filename,
			  GCompareFunc  func,
			  gpointer      user_data,
			  gsize        *length)
{
	struct archive *a;
	struct archive_entry *entry;
	char *ret = NULL;
	int r;

	*length = 0;

	a = archive_read_new ();
	archive_read_support_format_zip (a);
	r = archive_read_open_filename (a, filename, 10240);
	if (r != ARCHIVE_OK) {
		g_print ("Failed to open archive %s\n", filenames[0]);
		return NULL;
	}

	while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
		const char *name;

		name = archive_entry_pathname (entry);
		if (func (name, user_data) == 0) {
			size_t size = archive_entry_size (entry);
			char *buf;
			ssize_t read;

			buf = g_malloc (size);
			read = archive_read_data (a, buf, size);
			if (read <= 0) {
				g_free (buf);
			} else {
				ret = buf;
				*length = size;
			}
			break;
		}
		archive_read_data_skip(a);
	}
	archive_read_free(a);

	return ret;
}

int main (int argc, char **argv)
{
	char *input_filename;
	char *metafile;
	gsize length;
	char *cover_path;
	char *cover_data;
	GInputStream *mem_stream;

	GdkPixbuf *pixbuf;
	GError *error = NULL;
	GOptionContext *context;
	GFile *input;
	const char *output;

	/* Options parsing */
	context = g_option_context_new ("Thumbnail EPub books");
	g_option_context_add_main_entries (context, entries, NULL);

	if (g_option_context_parse (context, &argc, &argv, &error) == FALSE) {
		g_warning ("Couldn't parse command-line options: %s", error->message);
		g_error_free (error);
		return 1;
	}

	/* Set fatal warnings if required */
	if (g_fatal_warnings) {
		GLogLevelFlags fatal_mask;

		fatal_mask = g_log_set_always_fatal (G_LOG_FATAL_MASK);
		fatal_mask |= G_LOG_LEVEL_WARNING | G_LOG_LEVEL_CRITICAL;
		g_log_set_always_fatal (fatal_mask);
	}

	if (filenames == NULL || g_strv_length (filenames) != 2) {
		g_print ("Expects an input and an output file\n");
		return 1;
	}

	input = g_file_new_for_commandline_arg (filenames[0]);
	input_filename = g_file_get_path (input);
	g_object_unref (input);

	output = filenames[1];

	/* Look for the cover in the metafile */
	metafile = file_get_zipped_contents (input_filename, (GCompareFunc) g_strcmp0, "META-INF/container.xml", &length);
	cover_path = get_cover_path_from_metafile (metafile, length);
	g_free (metafile);
	if (cover_path != NULL) {
		cover_data = file_get_zipped_contents (input_filename, (GCompareFunc) g_strcmp0, cover_path, &length);
		g_free (cover_path);
	}

	/* Look for it by name instead */
	if (cover_data == NULL) {
		GRegex *regex;

		regex = g_regex_new (".*cover.*\\.(jpg|jpeg|png)",
				     G_REGEX_CASELESS, 0, NULL);
		cover_data = file_get_zipped_contents (input_filename, regex_matches, regex, &length);
	}

	mem_stream = g_memory_input_stream_new_from_data (cover_data, length, g_free);
	pixbuf = gdk_pixbuf_new_from_stream_at_scale (mem_stream, output_size, -1, TRUE, NULL, NULL);
	g_object_unref (mem_stream);

	if (gdk_pixbuf_save (pixbuf, output, "png", &error, NULL) == FALSE) {
		g_warning ("Couldn't save the thumbnail '%s' for file '%s': %s", output, filenames[0], error->message);
		g_error_free (error);
		return 1;
	}

	g_object_unref (pixbuf);

	return 0;
}
