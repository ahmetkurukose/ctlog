create table CTLog
(
    Url text not null
        constraint CTLog_pk
            primary key,
    HeadIndex int default 0 not null
);

create unique index CTLog_Url_uindex
    on CTLog (Url);

create table Certificate
(
    CN text not null,
    DN text not null,
    SerialNumber text not null,
    SAN int,
    constraint Certificate_pk
        primary key (CN, DN, SerialNumber)
);

create table Downloaded
(
    CN text not null,
    DN text not null,
    SerialNumber text not null,
    SAN int,
    constraint Downloaded_pk
        primary key (CN, DN, SerialNumber)
);

create table Monitor
(
    Email text not null,
    Domain text not null,
    constraint Monitor_pk
        primary key (Email, Domain)
);

