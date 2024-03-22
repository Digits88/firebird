/*
 *	PROGRAM:	JRD Access Method
 *	MODULE:		CharSetContainer.cpp
 *	DESCRIPTION:	Container for character set and it's collations
 *
 * The contents of this file are subject to the Interbase Public
 * License Version 1.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy
 * of the License at http://www.Inprise.com/IPL.html
 *
 * Software distributed under the License is distributed on an
 * "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, either express
 * or implied. See the License for the specific language governing
 * rights and limitations under the License.
 *
 * The Original Code was created by Inprise Corporation
 * and its predecessors. Portions created by Inprise Corporation are
 * Copyright (C) Inprise Corporation.
 *
 * All Rights Reserved.
 * Contributor(s): ______________________________________.
 *
 * Alex Peshkoff <peshkoff@mail.ru>
 */

#include "firebird.h"
#include "../jrd/CharSetContainer.h"

using namespace Jrd;

CharSetVers* CharSetVers::create(thread_db* tdbb, MemoryPool& pool, Cached::Charset* csp)
{
	return FB_NEW_POOL(pool) CharSetVers(csp);
}

void CharSetVers::destroy(CharSetVers* csv)
{
	delete csv;
}

MetaId CharSetContainer::getId()
{
	return cs->getId();
}

//	static Lock* makeLock(thread_db*, MemoryPool&);


