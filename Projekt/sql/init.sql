-- noinspection NonAsciiCharactersForFile

/*****************************************
 * @file Initialize sql database for iis project
 * @author Roman Fulla  <xfulla00>
 * @author Vojtěch Ulej <xulejv00>
 *****************************************/
DROP DATABASE IF EXISTS iis_soc_net;
CREATE DATABASE IF NOT EXISTS iis_soc_net;
USE iis_soc_net;
/**     DROP     **/
DROP TABLE IF EXISTS Users;
DROP TABLE IF EXISTS `Group`;
DROP TABLE IF EXISTS Thread;
DROP TABLE IF EXISTS Messages;
DROP TABLE IF EXISTS Moderate;
DROP TABLE IF EXISTS Is_member;
DROP TABLE IF EXISTS Applications;
DROP TABLE IF EXISTS Ranking;

/**     CREATE TABLES     **/
CREATE TABLE IF NOT EXISTS Users
(
	ID INT PRIMARY KEY AUTO_INCREMENT,
	Login VARCHAR(30) NOT NULL UNIQUE COLLATE utf8mb4_bin,
	Name VARCHAR(20) COLLATE utf8mb4_bin,
	Surname VARCHAR(20) COLLATE utf8mb4_bin,
	Description VARCHAR(2000) COLLATE utf8mb4_bin,
	Mode TINYINT DEFAULT 0,
	Password CHAR(97) NOT NULL,
	Image MEDIUMBLOB,
	Mimetype VARCHAR(20),
	-- FK
	Last_group INT DEFAULT NULL
    -- CONSTRAINT FK_group_users FOREIGN KEY (Last_group) REFERENCES `Group` (ID) ON DELETE CASCADE    -- Last Group visited
);

CREATE UNIQUE INDEX User_Login_uindex
	on iis_soc_net.Users (Login);



CREATE TABLE IF NOT EXISTS `Group` (
    ID                  INT PRIMARY KEY AUTO_INCREMENT,
    Name                VARCHAR(30) NOT NULL UNIQUE COLLATE utf8mb4_bin,
    Mode                TINYINT DEFAULT 0,
    Description         VARCHAR(2000) COLLATE utf8mb4_bin,
    Image               MEDIUMBLOB,
    Mimetype            VARCHAR(20),
    -- FK
    User_ID             INT NOT NULL,
    CONSTRAINT FK_user_group FOREIGN KEY (User_ID) REFERENCES Users (ID) ON DELETE CASCADE     -- vlastní
);

CREATE UNIQUE INDEX Group_name_uindex
	ON iis_soc_net.Group (Name);

CREATE TABLE IF NOT EXISTS Moderate (   -- Vazba <uživatel moderuje skupinu>
    ID      INT NOT NULL UNIQUE AUTO_INCREMENT, -- for easier mapping to sql alchemy orm
    User    INT NOT NULL,
    `Group`     INT NOT NULL,
    CONSTRAINT PK_moderate PRIMARY KEY (User,`Group`),
    CONSTRAINT FK_user_moderate FOREIGN KEY (User) REFERENCES Users (ID) ON DELETE CASCADE,
    CONSTRAINT FK_group_moderate FOREIGN KEY (`Group`) REFERENCES `Group` (ID) ON DELETE CASCADE
);

CREATE INDEX Moderate_user_index ON iis_soc_net.Moderate (User);

CREATE TABLE IF NOT EXISTS Is_member(   -- Vazba <uživatel je členem skupinu>
    ID      INT NOT NULL UNIQUE AUTO_INCREMENT, -- for easier mapping to sql alchemy orm
    User    INT NOT NULL,
    `Group`     INT NOT NULL,
    CONSTRAINT PK_is_member PRIMARY KEY (User, `Group`),
    CONSTRAINT FK_user_is_member FOREIGN KEY (User) REFERENCES Users (ID) ON DELETE CASCADE,
    CONSTRAINT FK_group_is_member FOREIGN KEY (`Group`) REFERENCES `Group` (ID) ON DELETE CASCADE
);

CREATE INDEX Is_member_user_index ON iis_soc_net.Is_member (User);

CREATE TABLE IF NOT EXISTS Applications(     -- Vazby <uživatel žádá o členství/ práva moderátora>
    ID      INT NOT NULL UNIQUE AUTO_INCREMENT,
    User          INT NOT NULL,
    `Group`       INT NOT NULL,
    Membership    BOOL DEFAULT TRUE,
    CONSTRAINT PK_application PRIMARY KEY (User, `Group`,Membership),
    CONSTRAINT FK_user_application FOREIGN KEY (User) REFERENCES Users (ID) ON DELETE CASCADE,
    CONSTRAINT FK_group_application FOREIGN KEY (`Group`) REFERENCES `Group` (ID) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS Thread (
    ID      INT NOT NULL UNIQUE AUTO_INCREMENT,
    Name               VARCHAR(30) NOT NULL COLLATE utf8mb4_bin,
    Description        VARCHAR(2000) COLLATE utf8mb4_bin,

    Group_ID           INT NOT NULL,   -- CK
    CONSTRAINT PK_thread PRIMARY KEY (Group_ID, Name),
    CONSTRAINT FK_group_thread FOREIGN KEY (Group_ID) REFERENCES `Group` (ID) ON DELETE CASCADE    -- má
);

CREATE TABLE IF NOT EXISTS Messages (
    ID             INT NOT NULL UNIQUE AUTO_INCREMENT,
    Content        VARCHAR(2000) COLLATE utf8mb4_bin,
    `Rank`         INT DEFAULT 0,
    Date_time      TIMESTAMP DEFAULT NOW(),

    User_ID        INT,  -- ck
    Thread_name    VARCHAR(30) NOT NULL COLLATE utf8mb4_bin,
    ID_group       INT NOT NULL,
    CONSTRAINT Pk_messages PRIMARY KEY (ID, Thread_name, ID_group),
    CONSTRAINT FK_user_messages FOREIGN KEY (User_ID) REFERENCES Users (ID) ON DELETE SET NULL,
    CONSTRAINT FK_thread_messages FOREIGN KEY (ID_group, Thread_name) REFERENCES Thread (Group_ID, Name) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS Ranking (
    Inc      BOOL DEFAULT NULL,
    User     INT NOT NULL,
    Message       INT NOT NULL,
    Message_author INT NOT NULL,
    Thread_name    VARCHAR(30) NOT NULL COLLATE utf8mb4_bin,
    ID_group      INT NOT NULL,
    CONSTRAINT PK_ranking PRIMARY KEY (User, Message, Thread_name,ID_group),
    CONSTRAINT FK_user_ranking FOREIGN KEY (User) REFERENCES Users (ID) ON DELETE CASCADE,
    CONSTRAINT FK_thread_ranking FOREIGN KEY (Message, Thread_name, ID_group) REFERENCES Messages (ID, Thread_name, ID_group) ON DELETE CASCADE
);

INSERT INTO Users (Name, Surname, Mode, Password, Login, Last_group) VALUES ('Ad', 'Min', 2, 'de29fefe1ec0ad7d92bae83d1026f5ad4b34763287861f0582ce12edce818a9e$7079bce6d49d3229153a15761cad36b3','Admin',1);
INSERT INTO `Group` (Name, Mode, Description, User_ID) VALUES ('Server_info', 0, 'Server info', (SELECT ID FROM Users WHERE Login = 'Admin'));