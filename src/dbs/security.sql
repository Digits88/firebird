/*
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
 * 2004.09.14 Alex Peshkoff - security changes, preventing ordinary users
 *		from access to other users crypted passwords and enabling modification
 *		of there own password. Originally suggested by Ivan Prenosil
 *		(see http://www.volny.cz/iprenosil/interbase/ for details).
 */

/* Domain definitions */
CREATE DOMAIN SYSTEM.PLG$PASSWD AS VARBINARY(64);
CREATE DOMAIN SYSTEM.PLG$ID AS INTEGER;

COMMIT;


/* Linger is definitely useful for security database */
ALTER DATABASE SET LINGER TO 60;	/* one minute */

COMMIT;


/*  Table: RDB$USERS */
CREATE TABLE SYSTEM.PLG$USERS (
	PLG$USER_NAME 		SYSTEM.SEC$USER_NAME NOT NULL PRIMARY KEY,
	PLG$GROUP_NAME		SYSTEM.SEC$USER_NAME,
	PLG$UID 			SYSTEM.PLG$ID,
	PLG$GID 			SYSTEM.PLG$ID,
	PLG$PASSWD 			SYSTEM.PLG$PASSWD NOT NULL,
	PLG$COMMENT 		SYSTEM.RDB$DESCRIPTION,
	PLG$FIRST_NAME 		SYSTEM.SEC$NAME_PART,
	PLG$MIDDLE_NAME		SYSTEM.SEC$NAME_PART,
	PLG$LAST_NAME		SYSTEM.SEC$NAME_PART);

COMMIT;


/*	VIEW: PLG$VIEW_USERS */
CREATE VIEW SYSTEM.PLG$VIEW_USERS (PLG$USER_NAME, PLG$GROUP_NAME, PLG$UID, PLG$GID, PLG$PASSWD,
		PLG$COMMENT, PLG$FIRST_NAME, PLG$MIDDLE_NAME, PLG$LAST_NAME) AS
	SELECT PLG$USER_NAME, PLG$GROUP_NAME, PLG$UID, PLG$GID, PLG$PASSWD,
		PLG$COMMENT, PLG$FIRST_NAME, PLG$MIDDLE_NAME, PLG$LAST_NAME
	FROM SYSTEM.PLG$USERS
	WHERE CURRENT_USER = 'SYSDBA'
	   OR CURRENT_ROLE = 'RDB$ADMIN'
	   OR CURRENT_USER = PLG$USERS.PLG$USER_NAME;

/*	Access rights */
GRANT ALL ON SYSTEM.PLG$USERS to VIEW SYSTEM.PLG$VIEW_USERS;
GRANT SELECT ON SYSTEM.PLG$VIEW_USERS to PUBLIC;
GRANT UPDATE(PLG$PASSWD, PLG$GROUP_NAME, PLG$UID, PLG$GID, PLG$FIRST_NAME, PLG$MIDDLE_NAME, PLG$LAST_NAME)
	ON SYSTEM.PLG$VIEW_USERS TO PUBLIC;

COMMIT;


/*	Needed record - with PASSWD = random + SHA1 (random + 'SYSDBA' + crypt('masterke')) */
INSERT INTO SYSTEM.PLG$USERS(PLG$USER_NAME, PLG$PASSWD, PLG$FIRST_NAME, PLG$MIDDLE_NAME, PLG$LAST_NAME)
	VALUES ('SYSDBA', 'NLtwcs9LrxLMOYhG0uGM9i6KS7mf3QAKvFVpmRg=', 'Sql', 'Server', 'Administrator');

COMMIT;
