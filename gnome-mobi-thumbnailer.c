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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */

#include <string.h>
#include <glib.h>

#include "gnome-thumbnailer-skeleton.h"

/* >H */
static guint16
get_guint16 (const char *data)
{
	guint16 *ptr = (guint16 *) (data);
	return GUINT16_FROM_BE (ptr[0]);
}

/* >L */
static guint32
get_guint32 (const char *data)
{
	guint32 *ptr = (guint32 *) (data);
	return GUINT32_FROM_BE (ptr[0]);
}

typedef struct {
	char *ident;
	unsigned short num_sections;
	GPtrArray *offsets;
} Sections;

static void
free_sections (Sections *sections)
{
	if (sections == NULL)
		return;
	g_free (sections->ident);
	g_ptr_array_free (sections->offsets, FALSE);
}

static Sections *
load_sections (GInputStream  *stream,
	       GError       **error)
{
	Sections *sections;
	char header[78];
	int i;
	char *sections_data;
	GPtrArray *array;

	if (g_input_stream_read (G_INPUT_STREAM (stream), &header, sizeof(header), NULL, error) < 0)
		return NULL;
	sections = g_new0 (Sections, 1);
	sections->ident = g_strndup (header + 0x3C, 8);
	g_debug ("ident '%s'", sections->ident);

	sections->num_sections = get_guint16 (header + 76);
	g_debug ("num sections '%d'", sections->num_sections);

	array = g_ptr_array_sized_new (sections->num_sections + 1);

	sections_data = g_malloc (sections->num_sections * 8);
	if (g_input_stream_read (G_INPUT_STREAM (stream), sections_data, sections->num_sections * 8, NULL, error) < 0) {
		return NULL;
	}
	for (i = 0; i < sections->num_sections * 2; i = i + 2) {
		guint32 item = get_guint32 (sections_data + i * sizeof (guint32));
		g_debug ("section %d: %u", i, item);
		g_ptr_array_add (array, GUINT_TO_POINTER (item));
	}
	/* Add this so there is an upper-boundary to the last section */
	g_ptr_array_add (array, GUINT_TO_POINTER (0xfffffff));

	sections->offsets = array;

	return sections;
}

static char *
get_section_data (GInputStream *stream,
		  Sections     *sections,
		  int           i,
		  gsize        *len)
{
	unsigned long before, after;
	gssize read;
	char *data;

	before = GPOINTER_TO_UINT (g_ptr_array_index (sections->offsets, i));
	after = GPOINTER_TO_UINT (g_ptr_array_index (sections->offsets, i + 1));
	g_seekable_seek (G_SEEKABLE (stream), before, G_SEEK_SET, NULL, NULL);

	data = g_malloc (after - before);
	read = g_input_stream_read (G_INPUT_STREAM (stream), data, after - before, NULL, NULL);

	*len = read;

	return data;
}

static int
get_cover_img_num (const char *header)
{
	guint32 len;
	const char *extheader;
	guint32 num_items, pos;
	guint i;

	len = get_guint32 (header + 20);
	extheader = header + 16 + len;

	if (!g_str_equal (extheader, "EXTH")) {
	        g_warning ("Corrupt or missing EXTH header");
		return -1;
	}

	num_items = get_guint32 (extheader + 8);
	g_debug ("num extheader items: %d", num_items);
	extheader = extheader + 12;

	pos = 0;
	for (i = 0; i < num_items; i++) {
		guint32 size, id;

		id = get_guint32 (extheader + pos);
		size = get_guint32 (extheader + pos + 4);
		/* 201 is CoverOffset */
		g_debug ("id %d", id);
		if (id == 201) {
			int ret;
			if (size != 12) {
				g_warning ("The CoverOffset record has the wrong size");
				return -1;
			}
			ret = get_guint32 (extheader + pos + 8);
			g_debug ("Found CoverOffset %d", ret);
			return ret;
		}
		pos += size;
	}

	return -1;
}

static int
get_image_section (GInputStream  *stream,
		   Sections      *sections,
		   GError       **error)
{
	char *header;
	gsize len;
	guint first_img;
	int image_num;

	header = get_section_data (G_INPUT_STREAM (stream), sections, 0, &len);

	/* Checking metadata availability */
	if (!(get_guint32 (header + 0x80) & 0x40)) {
		g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED, "File has no metadata");
		g_free (header);
		return -1;
	}

	/* Get the location of the first image */
	if (!g_str_equal (sections->ident, "TEXtREAd")) {
		first_img = get_guint32 (header + 0x6C);
		g_debug ("First image in MOBIBOOK mode: %d", first_img);
	} else {
		first_img = get_guint16 (header + 0x8);
		g_debug ("First image in TEXtREAd mode: %d", first_img);
	}

	image_num = get_cover_img_num (header);
	if (image_num < 0)
		return image_num;

	return first_img + image_num;
}

char *
file_to_data (const char  *path,
	      gsize       *ret_length,
	      GError     **error)
{
	Sections *sections;
	GFileInputStream *stream;
	GFile *input;
	GError *tmp_error = NULL;
	int image_num;
	char *ret;

	/* Open the file for reading */
	input = g_file_new_for_path (path);
	stream = g_file_read (input, NULL, error);
	g_object_unref (input);

	if (!stream)
		return NULL;

	sections = load_sections (G_INPUT_STREAM (stream), &tmp_error);
	if (sections == NULL || sections->ident == NULL)
		goto bail;
	if (!g_str_equal (sections->ident, "BOOKMOBI") &&
	    !g_str_equal (sections->ident, "TEXtREAd")) {
		if (tmp_error != NULL) {
			g_propagate_error (error, tmp_error);
		} else {
			g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "File is not in a recognised MOBI format '%s'", sections->ident);
		}
		goto bail;
	}

	image_num = get_image_section (G_INPUT_STREAM (stream), sections, &tmp_error);
	if (image_num < 0) {
		if (tmp_error != NULL) {
			g_propagate_error (error, tmp_error);
		} else {
			g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED, "Got an error getting the image number");
		}
		goto bail;
	}

	ret = get_section_data (G_INPUT_STREAM (stream), sections, image_num, ret_length);

	g_object_unref (stream);
	free_sections (sections);

	return ret;

bail:
	g_clear_object (&stream);
	free_sections (sections);
	return NULL;
}
