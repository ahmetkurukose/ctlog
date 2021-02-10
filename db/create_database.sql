create table certificate
(
    cn text not null,
    dn text not null,
    serialnumber text not null,
    san text,
    notbefore text,
    notafter text,
    issuer text,
    constraint certificate_pk
        primary key (cn, dn, serialnumber)
);

alter table certificate owner to postgres;

create table downloaded
(
    cn text not null,
    dn text not null,
    serialnumber text not null,
    san text,
    notbefore text,
    notafter text,
    issuer text,
    constraint downloaded_pk
        primary key (cn, dn, serialnumber)
);

alter table downloaded owner to postgres;

create table monitor
(
    email text not null,
    domain text not null,
    constraint monitor_pk
        primary key (email, domain)
);

alter table monitor owner to postgres;

create table ctlog
(
    url text not null
        constraint ctlog_pk
            primary key,
    headindex integer default 0 not null
);

alter table ctlog owner to postgres;

create unique index ctlog_url_uindex
    on ctlog (url);

