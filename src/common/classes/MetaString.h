/*
 *	PROGRAM:	Client/Server Common Code
 *	MODULE:		MetaString.h
 *	DESCRIPTION:	metadata name holder
 *
 *  The contents of this file are subject to the Initial
 *  Developer's Public License Version 1.0 (the "License");
 *  you may not use this file except in compliance with the
 *  License. You may obtain a copy of the License at
 *  http://www.ibphoenix.com/main.nfs?a=ibphoenix&page=ibp_idpl.
 *
 *  Software distributed under the License is distributed AS IS,
 *  WITHOUT WARRANTY OF ANY KIND, either express or implied.
 *  See the License for the specific language governing rights
 *  and limitations under the License.
 *
 *  The Original Code was created by Alexander Peshkov
 *  for the Firebird Open Source RDBMS project.
 *
 *  Copyright (c) 2005 Alexander Peshkov <peshkoff@mail.ru>
 *  and all contributors signed below.
 *
 *  All Rights Reserved.
 *  Contributor(s): ______________________________________.
 *
 *
 */

#ifndef METASTRING_H
#define METASTRING_H

#include "../common/classes/fb_string.h"
#include "../common/classes/fb_pair.h"
#include "../jrd/constants.h"

#ifdef SFIO
#include <stdio.h>
#endif

namespace Firebird {

class MetaString
{
private:
	char data[MAX_SQL_IDENTIFIER_SIZE];
	unsigned int count;

	void init()
	{
		memset(data, 0, MAX_SQL_IDENTIFIER_SIZE);
	}
	MetaString& set(const MetaString& m)
	{
		memcpy(data, m.data, MAX_SQL_IDENTIFIER_SIZE);
		count = m.count;
		return *this;
	}

public:
	MetaString() { init(); count = 0; }
	MetaString(const char* s) { assign(s); }
	MetaString(const char* s, FB_SIZE_T l) { assign(s, l); }
	MetaString(const MetaString& m) { set(m); }
	MetaString(const AbstractString& s) { assign(s.c_str(), s.length()); }
	explicit MetaString(MemoryPool&) { init(); count = 0; }
	MetaString(MemoryPool&, const char* s) { assign(s); }
	MetaString(MemoryPool&, const char* s, FB_SIZE_T l) { assign(s, l); }
	MetaString(MemoryPool&, const MetaString& m) { set(m); }
	MetaString(MemoryPool&, const AbstractString& s) { assign(s.c_str(), s.length()); }

	MetaString& assign(const char* s, FB_SIZE_T l);
	MetaString& assign(const char* s) { return assign(s, s ? fb_strlen(s) : 0); }
	MetaString& clear() { return assign(nullptr, 0); }
	MetaString& operator=(const char* s) { return assign(s); }
	MetaString& operator=(const AbstractString& s) { return assign(s.c_str(), s.length()); }
	MetaString& operator=(const MetaString& m) { return set(m); }
	char* getBuffer(const FB_SIZE_T l);

	FB_SIZE_T length() const { return count; }
	const char* c_str() const { return data; }
	const char* nullStr() const { return (count == 0 ? NULL : data); }
	bool isEmpty() const { return count == 0; }
	bool hasData() const { return count != 0; }

	char& operator[](unsigned n) { return data[n]; }
	char operator[](unsigned n) const { return data[n]; }

	const char* begin() const { return data; }
	const char* end() const { return data + count; }

	int compare(const char* s, FB_SIZE_T l) const;
	int compare(const char* s) const { return compare(s, s ? fb_strlen(s) : 0); }
	int compare(const AbstractString& s) const { return compare(s.c_str(), s.length()); }
	int compare(const MetaString& m) const { return memcmp(data, m.data, MAX_SQL_IDENTIFIER_SIZE); }

	string toQuotedString() const
	{
		string s;

		if (hasData())
		{
			s.append("\"");

			for (const auto c : *this)
			{
				if (c == '"')
					s.append("\"");

				s.append(&c, 1);
			}

			s.append("\"");
		}

		return s;
	}

	bool operator==(const char* s) const { return compare(s) == 0; }
	bool operator!=(const char* s) const { return compare(s) != 0; }
	bool operator==(const AbstractString& s) const { return compare(s) == 0; }
	bool operator!=(const AbstractString& s) const { return compare(s) != 0; }
	bool operator==(const MetaString& m) const { return compare(m) == 0; }
	bool operator!=(const MetaString& m) const { return compare(m) != 0; }
	bool operator<=(const MetaString& m) const { return compare(m) <= 0; }
	bool operator>=(const MetaString& m) const { return compare(m) >= 0; }
	bool operator< (const MetaString& m) const { return compare(m) <  0; }
	bool operator> (const MetaString& m) const { return compare(m) >  0; }

	void printf(const char*, ...);
	FB_SIZE_T copyTo(char* to, FB_SIZE_T toSize) const;

protected:
	static void adjustLength(const char* const s, FB_SIZE_T& l);
};

template <typename T>
class BaseQualifiedName
{
public:
	explicit BaseQualifiedName(MemoryPool& p, const T& aObject,
			const T& aSchema = {}, const T& aPackage = {})
		: object(p, aObject),
		  schema(p, aSchema),
		  package(p, aPackage)
	{
	}

	explicit BaseQualifiedName(const T& aObject, const T& aSchema = {}, const T& aPackage = {})
		: object(aObject),
		  schema(aSchema),
		  package(aPackage)
	{
	}

	BaseQualifiedName(MemoryPool& p, const BaseQualifiedName& src)
		: object(p, src.object),
		  schema(p, src.schema),
		  package(p, src.package)
	{
	}

	BaseQualifiedName(const BaseQualifiedName& src)
		: object(src.object),
		  schema(src.schema),
		  package(src.package)
	{
	}

	explicit BaseQualifiedName(MemoryPool& p)
		: object(p),
		  schema(p),
		  package(p)
	{
	}

	BaseQualifiedName()
	{
	}

public:
	static BaseQualifiedName<T> parse(const string& str)
	{
		// FIXME: parse
		return BaseQualifiedName<T>(str);
	}

public:
	bool operator<(const BaseQualifiedName& m) const
	{
		return schema < m.schema ||
			(schema == m.schema && object < m.object) ||
			(schema == m.schema && object == m.object && package < m.package);
	}

	bool operator>(const BaseQualifiedName& m) const
	{
		return schema > m.schema ||
			(schema == m.schema && object > m.object) ||
			(schema == m.schema && object == m.object && package > m.package);
	}

	bool operator==(const BaseQualifiedName& m) const
	{
		return schema == m.schema && object == m.object && package == m.package;
	}

	bool operator!=(const BaseQualifiedName& m) const
	{
		return !(*this == m);
	}

public:
	BaseQualifiedName getSchemaAndPackage() const
	{
		return BaseQualifiedName(package, schema);
	}

	void clear()
	{
		object = {};
		schema = {};
		package = {};
	}

	Firebird::string toString() const
	{
		Firebird::string s;

		const auto appendName = [&s](const T& name) {
			if (name.hasData())
			{
				s += name.toQuotedString();
				return true;
			}

			return false;
		};

		if (appendName(schema))
			s.append(".");

		if (appendName(package))
			s.append(".");

		appendName(object);

		return s;
	}

public:
	T object;
	T schema;
	T package;
};

using QualifiedMetaString = Firebird::BaseQualifiedName<MetaString>;

} // namespace Firebird

#endif // METASTRING_H
