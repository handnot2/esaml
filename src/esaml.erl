%% esaml - SAML for erlang
%%
%% Copyright (c) 2013, Alex Wilson and the University of Queensland
%% All rights reserved.
%%
%% Distributed subject to the terms of the 2-clause BSD license, see
%% the LICENSE file in the root of the distribution.

%% @doc SAML for Erlang
-module(esaml).
-behaviour(application).
-behaviour(supervisor).

-include_lib("xmerl/include/xmerl.hrl").
-include_lib("public_key/include/public_key.hrl").
-include("esaml.hrl").

-export([start/2, stop/1, init/1]).
-export([stale_time/1]).
-export([config/2, config/1, to_xml/1, decode_response/1, decode_assertion/1, validate_assertion/3]).
-export([decode_logout_request/1, decode_logout_response/1, decode_idp_metadata/1]).

-type org() :: #esaml_org{}.
-type contact() :: #esaml_contact{}.
-type sp_metadata() :: #esaml_sp_metadata{}.
-type idp_metadata() :: #esaml_idp_metadata{}.
-type authnreq() :: #esaml_authnreq{}.
-type subject() :: #esaml_subject{}.
-type assertion() :: #esaml_assertion{}.
-type logoutreq() :: #esaml_logoutreq{}.
-type logoutresp() :: #esaml_logoutresp{}.
-type response() :: #esaml_response{}.
-type sp() :: #esaml_sp{}.
-type saml_record() :: org() | contact() | sp_metadata() | idp_metadata() | authnreq() | subject() | assertion() | logoutreq() | logoutresp() | response().

-export_type([org/0, contact/0, sp_metadata/0, idp_metadata/0,
    authnreq/0, subject/0, assertion/0, logoutreq/0,
    logoutresp/0, response/0, sp/0, saml_record/0]).

-type localized_string() :: string() | [{Locale :: atom(), LocalizedString :: string()}].
-type name_format() :: email | x509 | windows | krb | persistent | transient | unknown.
-type logout_reason() :: user | admin.
-type status_code() :: success | request_error | response_error | bad_version | authn_failed | bad_attr | denied | bad_binding | unknown.
-type version() :: string().
-type datetime() :: string() | binary().
-type condition() :: {not_before, esaml:datetime()} | {not_on_or_after, esaml:datetime()} | {audience, string()}.
-type conditions() :: [condition()].
-export_type([localized_string/0, name_format/0, logout_reason/0, status_code/0, version/0, datetime/0, conditions/0]).

%% @private
start(_StartType, _StartArgs) ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

%% @private
stop(_State) ->
    ok.

%% @private
init([]) ->
    DupeEts = {esaml_ets_table_owner,
        {esaml_util, start_ets, []},
        permanent, 5000, worker, [esaml]},
    {ok,
        {{one_for_one, 60, 600},
        [DupeEts]}}.

%% @doc Retrieve a config record
-spec config(Name :: atom()) -> term() | undefined.
config(N) -> config(N, undefined).
%% @doc Retrieve a config record with default
-spec config(Name :: atom(), Default :: term()) -> term().
config(N, D) ->
    case application:get_env(esaml, N) of
        {ok, V} -> V;
        _ -> D
    end.

-spec nameid_map(string()) -> name_format().
nameid_map("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress") -> email;
nameid_map("urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName") -> x509;
nameid_map("urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName") -> windows;
nameid_map("urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos") -> krb;
nameid_map("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent") -> persistent;
nameid_map("urn:oasis:names:tc:SAML:2.0:nameid-format:transient") -> transient;
nameid_map(S) when is_list(S) -> unknown.

-spec nameid_name_qualifier_map(string()) -> undefined | string().
nameid_name_qualifier_map("") -> undefined;
nameid_name_qualifier_map(S) when is_list(S) -> S.

-spec nameid_sp_name_qualifier_map(string()) -> undefined | string().
nameid_sp_name_qualifier_map("") -> undefined;
nameid_sp_name_qualifier_map(S) when is_list(S) -> S.

-spec nameid_format_map(string()) -> undefined | string().
nameid_format_map("") -> undefined;
nameid_format_map(S) when is_list(S) -> S.

-spec subject_method_map(string()) -> bearer | unknown.
subject_method_map("urn:oasis:names:tc:SAML:2.0:cm:bearer") -> bearer;
subject_method_map(_) -> unknown.

-spec status_code_map(string()) -> status_code() | atom().
status_code_map("urn:oasis:names:tc:SAML:2.0:status:Success") -> success;
status_code_map("urn:oasis:names:tc:SAML:2.0:status:VersionMismatch") -> bad_version;
status_code_map("urn:oasis:names:tc:SAML:2.0:status:AuthnFailed") -> authn_failed;
status_code_map("urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue") -> bad_attr;
status_code_map("urn:oasis:names:tc:SAML:2.0:status:RequestDenied") -> denied;
status_code_map("urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding") -> bad_binding;
status_code_map(Urn = "urn:" ++ _) -> list_to_atom(lists:last(string:tokens(Urn, ":")));
status_code_map(S) when is_list(S) -> unknown.

-spec rev_status_code_map(status_code()) -> string().
rev_status_code_map(success) -> "urn:oasis:names:tc:SAML:2.0:status:Success";
rev_status_code_map(bad_version) -> "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch";
rev_status_code_map(authn_failed) -> "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed";
rev_status_code_map(bad_attr) -> "urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue";
rev_status_code_map(denied) -> "urn:oasis:names:tc:SAML:2.0:status:RequestDenied";
rev_status_code_map(bad_binding) -> "urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding";
rev_status_code_map(_) -> error(bad_status_code).

-spec logout_reason_map(string()) -> logout_reason().
logout_reason_map("urn:oasis:names:tc:SAML:2.0:logout:user") -> user;
logout_reason_map("urn:oasis:names:tc:SAML:2.0:logout:admin") -> admin;
logout_reason_map(S) when is_list(S) -> unknown.

-spec rev_logout_reason_map(logout_reason()) -> string().
rev_logout_reason_map(user) -> "urn:oasis:names:tc:SAML:2.0:logout:user";
rev_logout_reason_map(admin) -> "urn:oasis:names:tc:SAML:2.0:logout:admin".

-spec common_attrib_map(string()) -> atom().
common_attrib_map("urn:oid:2.16.840.1.113730.3.1.3") -> employeeNumber;
common_attrib_map("urn:oid:1.3.6.1.4.1.5923.1.1.1.6") -> eduPersonPrincipalName;
common_attrib_map("urn:oid:0.9.2342.19200300.100.1.3") -> mail;
common_attrib_map("urn:oid:2.5.4.42") -> givenName;
common_attrib_map("urn:oid:2.16.840.1.113730.3.1.241") -> displayName;
common_attrib_map("urn:oid:2.5.4.3") -> commonName;
common_attrib_map("urn:oid:2.5.4.20") -> telephoneNumber;
common_attrib_map("urn:oid:2.5.4.10") -> organizationName;
common_attrib_map("urn:oid:2.5.4.11") -> organizationalUnitName;
common_attrib_map("urn:oid:1.3.6.1.4.1.5923.1.1.1.9") -> eduPersonScopedAffiliation;
common_attrib_map("urn:oid:2.16.840.1.113730.3.1.4") -> employeeType;
common_attrib_map("urn:oid:0.9.2342.19200300.100.1.1") -> uid;
common_attrib_map("urn:oid:2.5.4.4") -> surName;
common_attrib_map(Uri = "http://" ++ _) -> list_to_atom(lists:last(string:tokens(Uri, "/")));
common_attrib_map(Other) when is_list(Other) -> list_to_atom(Other).

-include("xmerl_xpath_macros.hrl").

-spec decode_idp_metadata(Xml :: #xmlElement{}) -> {ok, #esaml_idp_metadata{}} | {error, term()}.
decode_idp_metadata(Xml) ->
    Ns = [{"samlp", 'urn:oasis:names:tc:SAML:2.0:protocol'},
          {"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'},
          {"md", 'urn:oasis:names:tc:SAML:2.0:metadata'},
          {"ds", 'http://www.w3.org/2000/09/xmldsig#'}],
    esaml_util:threaduntil([
        ?xpath_attr_required("/md:EntityDescriptor/@entityID", esaml_idp_metadata, entity_id, bad_entity),
        ?xpath_attr_required("/md:EntityDescriptor/md:IDPSSODescriptor/md:SingleSignOnService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST']/@Location",
            esaml_idp_metadata, login_location, missing_sso_location),
        ?xpath_attr("/md:EntityDescriptor/md:IDPSSODescriptor/md:SingleLogoutService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST']/@Location",
            esaml_idp_metadata, logout_location),
        ?xpath_text("/md:EntityDescriptor/md:IDPSSODescriptor/md:NameIDFormat/text()",
            esaml_idp_metadata, name_format, fun nameid_map/1),
        ?xpath_text_mult("/md:EntityDescriptor/md:IDPSSODescriptor/md:KeyDescriptor[@use='signing']/ds:KeyInfo/ds:X509Data/ds:X509Certificate/text()",
            esaml_idp_metadata, certificates, fun(X) -> base64:decode(list_to_binary(X)) end),
        ?xpath_recurse("/md:EntityDescriptor/md:ContactPerson[@contactType='technical']", esaml_idp_metadata, tech, decode_contact),
        ?xpath_recurse("/md:EntityDescriptor/md:Organization", esaml_idp_metadata, org, decode_org)
    ], #esaml_idp_metadata{}).

%% @private
-spec decode_org(Xml :: #xmlElement{}) -> {ok, #esaml_org{}} | {error, term()}.
decode_org(Xml) ->
    Ns = [{"samlp", 'urn:oasis:names:tc:SAML:2.0:protocol'},
          {"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'},
          {"md", 'urn:oasis:names:tc:SAML:2.0:metadata'}],
    esaml_util:threaduntil([
        ?xpath_text_required("/md:Organization/md:OrganizationName/text()", esaml_org, name, bad_org),
        ?xpath_text("/md:Organization/md:OrganizationDisplayName/text()", esaml_org, displayname),
        ?xpath_text("/md:Organization/md:OrganizationURL/text()", esaml_org, url)
    ], #esaml_org{}).

%% @private
-spec decode_contact(Xml :: #xmlElement{}) -> {ok, #esaml_contact{}} | {error, term()}.
decode_contact(Xml) ->
    Ns = [{"samlp", 'urn:oasis:names:tc:SAML:2.0:protocol'},
          {"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'},
          {"md", 'urn:oasis:names:tc:SAML:2.0:metadata'}],
    esaml_util:threaduntil([
        ?xpath_text_required("/md:ContactPerson/md:EmailAddress/text()", esaml_contact, email, bad_contact),
        ?xpath_text("/md:ContactPerson/md:GivenName/text()", esaml_contact, name),
        ?xpath_text_append("/md:ContactPerson/md:SurName/text()", esaml_contact, name, " ")
    ], #esaml_contact{}).

%% @private
-spec decode_logout_request(Xml :: #xmlElement{}) -> {ok, #esaml_logoutreq{}} | {error, term()}.
decode_logout_request(Xml) ->
    Ns = [{"samlp", 'urn:oasis:names:tc:SAML:2.0:protocol'},
          {"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'}],
    esaml_util:threaduntil([
        ?xpath_attr_required("/samlp:LogoutRequest/@Version", esaml_logoutreq, version, bad_version),
        ?xpath_attr_required("/samlp:LogoutRequest/@IssueInstant", esaml_logoutreq, issue_instant, bad_response),
        ?xpath_text_required("/samlp:LogoutRequest/saml:NameID/text()", esaml_logoutreq, name, bad_name),
        ?xpath_attr("/samlp:LogoutRequest/saml:NameID/@SPNameQualifier", esaml_logoutreq, sp_name_qualifier, fun nameid_sp_name_qualifier_map/1),
        ?xpath_attr("/samlp:LogoutRequest/saml:NameID/@Format", esaml_logoutreq, name_format, fun nameid_format_map/1),
        ?xpath_attr("/samlp:LogoutRequest/@Destination", esaml_logoutreq, destination),
        ?xpath_attr("/samlp:LogoutRequest/@Reason", esaml_logoutreq, reason, fun logout_reason_map/1),
        ?xpath_text("/samlp:LogoutRequest/saml:Issuer/text()", esaml_logoutreq, issuer)
    ], #esaml_logoutreq{}).

%% @private
-spec decode_logout_response(Xml :: #xmlElement{}) -> {ok, #esaml_logoutresp{}} | {error, term()}.
decode_logout_response(Xml) ->
    Ns = [{"samlp", 'urn:oasis:names:tc:SAML:2.0:protocol'},
          {"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'}],
    esaml_util:threaduntil([
        ?xpath_attr_required("/samlp:LogoutResponse/@Version", esaml_logoutresp, version, bad_version),
        ?xpath_attr_required("/samlp:LogoutResponse/@IssueInstant", esaml_logoutresp, issue_instant, bad_response),
        ?xpath_attr_required("/samlp:LogoutResponse/samlp:Status/samlp:StatusCode/@Value", esaml_logoutresp, status, fun status_code_map/1, bad_response),
        ?xpath_attr("/samlp:LogoutResponse/@Destination", esaml_logoutresp, destination),
        ?xpath_text("/samlp:LogoutResponse/saml:Issuer/text()", esaml_logoutresp, issuer)
    ], #esaml_logoutresp{}).

%% @private
-spec decode_response(Xml :: #xmlElement{}) -> {ok, #esaml_response{}} | {error, term()}.
decode_response(Xml) ->
    Ns = [{"samlp", 'urn:oasis:names:tc:SAML:2.0:protocol'},
          {"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'}],
    esaml_util:threaduntil([
        ?xpath_attr_required("/samlp:Response/@Version", esaml_response, version, bad_version),
        ?xpath_attr_required("/samlp:Response/@IssueInstant", esaml_response, issue_instant, bad_response),
        ?xpath_attr("/samlp:Response/@Destination", esaml_response, destination),
        ?xpath_text("/samlp:Response/saml:Issuer/text()", esaml_response, issuer),
        ?xpath_attr("/samlp:Response/samlp:Status/samlp:StatusCode/@Value", esaml_response, status, fun status_code_map/1),
        ?xpath_recurse("/samlp:Response/saml:Assertion", esaml_response, assertion, decode_assertion)
    ], #esaml_response{}).

%% @private
-spec decode_assertion(Xml :: #xmlElement{}) -> {ok, #esaml_assertion{}} | {error, term()}.
decode_assertion(Xml) ->
    Ns = [{"samlp", 'urn:oasis:names:tc:SAML:2.0:protocol'},
          {"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'}],
    esaml_util:threaduntil([
        ?xpath_attr_required("/saml:Assertion/@Version", esaml_assertion, version, bad_version),
        ?xpath_attr_required("/saml:Assertion/@IssueInstant", esaml_assertion, issue_instant, bad_assertion),
        ?xpath_attr_required("/saml:Assertion/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@Recipient", esaml_assertion, recipient, bad_recipient),
        ?xpath_text("/saml:Assertion/saml:Issuer/text()", esaml_assertion, issuer),
        ?xpath_recurse("/saml:Assertion/saml:Subject", esaml_assertion, subject, decode_assertion_subject),
        ?xpath_recurse("/saml:Assertion/saml:Conditions", esaml_assertion, conditions, decode_assertion_conditions),
        ?xpath_recurse("/saml:Assertion/saml:AttributeStatement", esaml_assertion, attributes, decode_assertion_attributes),
        ?xpath_recurse("/saml:Assertion/saml:AuthnStatement", esaml_assertion, authn, decode_assertion_authn)
    ], #esaml_assertion{}).

-spec decode_assertion_subject(#xmlElement{}) -> {ok, #esaml_subject{}} | {error, term()}.
decode_assertion_subject(Xml) ->
    Ns = [{"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'}],
    esaml_util:threaduntil([
        ?xpath_text("/saml:Subject/saml:NameID/text()", esaml_subject, name),
        ?xpath_attr("/saml:Subject/saml:NameID/@NameQualifier", esaml_subject, name_qualifier, fun nameid_name_qualifier_map/1),
        ?xpath_attr("/saml:Subject/saml:NameID/@SPNameQualifier", esaml_subject, sp_name_qualifier, fun nameid_sp_name_qualifier_map/1),
        ?xpath_attr("/saml:Subject/saml:NameID/@Format", esaml_subject, name_format, fun nameid_format_map/1),
        ?xpath_attr("/saml:Subject/saml:SubjectConfirmation/@Method", esaml_subject, confirmation_method, fun subject_method_map/1),
        ?xpath_attr("/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@NotOnOrAfter", esaml_subject, notonorafter),
        ?xpath_attr("/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@InResponseTo", esaml_subject, in_response_to)
    ], #esaml_subject{}).

-spec decode_assertion_conditions(#xmlElement{}) -> {ok, conditions()} | {error, term()}.
decode_assertion_conditions(Xml) ->
    Ns = [{"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'}],
    esaml_util:threaduntil([
        fun(C) ->
            case xmerl_xpath:string("/saml:Conditions/@NotBefore", Xml, [{namespace, Ns}]) of
                [#xmlAttribute{value = V}] -> [{not_before, V} | C]; _ -> C
            end
        end,
        fun(C) ->
            case xmerl_xpath:string("/saml:Conditions/@NotOnOrAfter", Xml, [{namespace, Ns}]) of
                [#xmlAttribute{value = V}] -> [{not_on_or_after, V} | C]; _ -> C
            end
        end,
        fun(C) ->
            case xmerl_xpath:string("/saml:Conditions/saml:AudienceRestriction/saml:Audience/text()", Xml, [{namespace, Ns}]) of
                [#xmlText{value = V}] -> [{audience, V} | C]; _ -> C
            end
        end
    ], []).

-spec decode_assertion_attributes(#xmlElement{}) -> {ok, [{atom(), string()}]} | {error, term()}.
decode_assertion_attributes(Xml) ->
    Ns = [{"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'}],
    Attrs = xmerl_xpath:string("/saml:AttributeStatement/saml:Attribute", Xml, [{namespace, Ns}]),
    {ok, lists:foldl(fun(AttrElem, In) ->
        case [X#xmlAttribute.value || X <- AttrElem#xmlElement.attributes, X#xmlAttribute.name =:= 'Name'] of
            [Name] ->
                case xmerl_xpath:string("saml:AttributeValue/text()", AttrElem, [{namespace, Ns}]) of
                    [#xmlText{value = Value}] ->
                        [{common_attrib_map(Name), Value} | In];
                    List ->
                        if (length(List) > 0) ->
                            Value = [X#xmlText.value || X <- List, element(1, X) =:= xmlText],
                            [{common_attrib_map(Name), Value} | In];
                        true ->
                            In
                        end
                end;
            _ -> In
        end
    end, [], Attrs)}.

-spec decode_assertion_authn(#xmlElement{}) -> {ok, conditions()} | {error, term()}.
decode_assertion_authn(Xml) ->
    Ns = [{"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'}],
    esaml_util:threaduntil([
        fun(C) ->
            case xmerl_xpath:string("/saml:AuthnStatement/@AuthnInstant", Xml, [{namespace, Ns}]) of
                [#xmlAttribute{value = V}] -> [{authn_instant, V} | C]; _ -> C
            end
        end,
        fun(C) ->
            case xmerl_xpath:string("/saml:AuthnStatement/@SessionNotOnOrAfter", Xml, [{namespace, Ns}]) of
                [#xmlAttribute{value = V}] -> [{session_not_on_or_after, V} | C]; _ -> C
            end
        end,
        fun(C) ->
            case xmerl_xpath:string("/saml:AuthnStatement/@SessionIndex", Xml, [{namespace, Ns}]) of
                [#xmlAttribute{value = V}] -> [{session_index, V} | C]; _ -> C
            end
        end,
        fun(C) ->
            case xmerl_xpath:string("/saml:AuthnStatement/saml:AuthnContext/saml:AuthnContextClassRef/text()", Xml, [{namespace, Ns}]) of
                [#xmlText{value = V}] -> [{authn_context, V} | C]; _ -> C
            end
        end
    ], []).

%% @doc Returns the time at which an assertion is considered stale.
%% @private
-spec stale_time(#esaml_assertion{}) -> integer().
stale_time(A) ->
    esaml_util:thread([
        fun(T) ->
            case A#esaml_assertion.subject of
                #esaml_subject{notonorafter = ""} -> T;
                #esaml_subject{notonorafter = Restrict} ->
                    Secs = calendar:datetime_to_gregorian_seconds(
                        esaml_util:saml_to_datetime(Restrict)),
                    if (Secs < T) -> Secs; true -> T end
            end
        end,
        fun(T) ->
            Conds = A#esaml_assertion.conditions,
            case proplists:get_value(not_on_or_after, Conds) of
                undefined -> T;
                Restrict ->
                    Secs = calendar:datetime_to_gregorian_seconds(
                        esaml_util:saml_to_datetime(Restrict)),
                    if (Secs < T) -> Secs; true -> T end
            end
        end,
        fun(T) ->
            if (T =:= none) ->
                II = A#esaml_assertion.issue_instant,
                IISecs = calendar:datetime_to_gregorian_seconds(
                    esaml_util:saml_to_datetime(II)),
                IISecs + 5*60;
            true ->
                T
            end
        end
    ], none).

check_stale(A) ->
    Now = erlang:localtime_to_universaltime(erlang:localtime()),
    NowSecs = calendar:datetime_to_gregorian_seconds(Now),
    T = stale_time(A),
    if (NowSecs > T) ->
        {error, stale_assertion};
    true ->
        A
    end.

%% @doc Parse and validate an assertion, returning it as a record
%% @private
-spec validate_assertion(AssertionXml :: #xmlElement{}, Recipient :: string(), Audience :: string()) ->
        {ok, #esaml_assertion{}} | {error, Reason :: term()}.
validate_assertion(AssertionXml, Recipient, Audience) ->
    case decode_assertion(AssertionXml) of
        {error, Reason} ->
            {error, Reason};
        {ok, Assertion} ->
            esaml_util:threaduntil([
                fun(A) -> case A of
                    #esaml_assertion{version = "2.0"} -> A;
                    _ -> {error, bad_version}
                end end,
                fun(A) -> case A of
                    #esaml_assertion{recipient = Recipient} -> A;
                    _ -> {error, bad_recipient}
                end end,
                fun(A) -> case A of
                    #esaml_assertion{conditions = Conds} ->
                        case proplists:get_value(audience, Conds) of
                            undefined -> A;
                            Audience -> A;
                            _ -> {error, bad_audience}
                        end;
                    _ -> A
                end end,
                fun check_stale/1
            ], Assertion)
    end.

%% @doc Produce cloned elements with xml:lang set to represent
%%      multi-locale strings.
%% @private
-spec lang_elems(#xmlElement{}, localized_string()) -> [#xmlElement{}].
lang_elems(BaseTag, Vals = [{Lang, _} | _]) when is_atom(Lang) ->
    [BaseTag#xmlElement{
        attributes = BaseTag#xmlElement.attributes ++
            [#xmlAttribute{name = 'xml:lang', value = atom_to_list(L)}],
        content = BaseTag#xmlElement.content ++
            [#xmlText{value = V}]} || {L,V} <- Vals];
lang_elems(BaseTag, Val) ->
    [BaseTag#xmlElement{
        attributes = BaseTag#xmlElement.attributes ++
            [#xmlAttribute{name = 'xml:lang', value = "en"}],
        content = BaseTag#xmlElement.content ++
            [#xmlText{value = Val}]}].

%% @doc Convert a SAML request/metadata record into XML
%% @private
-spec to_xml(saml_record()) -> #xmlElement{}.
to_xml(#esaml_authnreq{version = V, issue_instant = Time, destination = Dest,
        issuer = Issuer, name_format = Format, consumer_location = Consumer}) ->
    Ns = #xmlNamespace{nodes = [{"samlp", 'urn:oasis:names:tc:SAML:2.0:protocol'},
                                {"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'}]},

    esaml_util:build_nsinfo(Ns, #xmlElement{name = 'samlp:AuthnRequest',
        attributes = [#xmlAttribute{name = 'xmlns:samlp', value = proplists:get_value("samlp", Ns#xmlNamespace.nodes)},
                      #xmlAttribute{name = 'xmlns:saml', value = proplists:get_value("saml", Ns#xmlNamespace.nodes)},
                      #xmlAttribute{name = 'IssueInstant', value = Time},
                      #xmlAttribute{name = 'Version', value = V},
                      #xmlAttribute{name = 'Destination', value = Dest},
                      #xmlAttribute{name = 'AssertionConsumerServiceURL', value = Consumer},
                      #xmlAttribute{name = 'ProtocolBinding', value = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"}],
        content = [#xmlElement{name = 'saml:Issuer', content = [#xmlText{value = Issuer}]}] ++
              case is_list(Format) of
                true ->
                    [#xmlElement{name = 'samlp:NameIDPolicy',
                        attributes = [#xmlAttribute{name = 'Format', value = Format}]}];
                false ->
                    []
              end
    });

to_xml(#esaml_logoutreq{version = V, issue_instant = Time, destination = Dest, issuer = Issuer,
                        name = NameID, name_qualifier = NameQualifier,
                        sp_name_qualifier = SPNameQualifier, name_format = NameFormat,
                        session_index = SessionIndex, reason = Reason}) ->
    Ns = #xmlNamespace{nodes = [{"samlp", 'urn:oasis:names:tc:SAML:2.0:protocol'},
                                {"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'}]},
    NameIDAttrs =
        case is_list(NameQualifier) of
            true -> [#xmlAttribute{name = 'NameQualifier', value = NameQualifier}];
            false -> []
        end ++
        case is_list(SPNameQualifier) of
            true -> [#xmlAttribute{name = 'SPNameQualifier', value = SPNameQualifier}];
            false -> []
        end ++
        case is_list(NameFormat) of
            true -> [#xmlAttribute{name = 'Format', value = NameFormat}];
            false -> []
        end,
    esaml_util:build_nsinfo(Ns, #xmlElement{name = 'samlp:LogoutRequest',
        attributes = [#xmlAttribute{name = 'xmlns:samlp', value = proplists:get_value("samlp", Ns#xmlNamespace.nodes)},
                      #xmlAttribute{name = 'xmlns:saml', value = proplists:get_value("saml", Ns#xmlNamespace.nodes)},
                      #xmlAttribute{name = 'IssueInstant', value = Time},
                      #xmlAttribute{name = 'Version', value = V},
                      #xmlAttribute{name = 'Destination', value = Dest},
                      #xmlAttribute{name = 'Reason', value = rev_logout_reason_map(Reason)}],
        content = [
            #xmlElement{name = 'saml:Issuer', content = [#xmlText{value = Issuer}]},
            #xmlElement{name = 'saml:NameID',
                attributes = NameIDAttrs,
                content = [#xmlText{value = NameID}]},
            #xmlElement{name = 'samlp:SessionIndex', content = [#xmlText{value = SessionIndex}]}
        ]
    });

to_xml(#esaml_logoutresp{version = V, issue_instant  = Time,
    destination = Dest, issuer = Issuer, status = Status}) ->
    Ns = #xmlNamespace{nodes = [{"samlp", 'urn:oasis:names:tc:SAML:2.0:protocol'},
                                {"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'}]},
    esaml_util:build_nsinfo(Ns, #xmlElement{name = 'samlp:LogoutResponse',
        attributes = [#xmlAttribute{name = 'xmlns:samlp', value = proplists:get_value("samlp", Ns#xmlNamespace.nodes)},
                      #xmlAttribute{name = 'xmlns:saml', value = proplists:get_value("saml", Ns#xmlNamespace.nodes)},
                      #xmlAttribute{name = 'IssueInstant', value = Time},
                      #xmlAttribute{name = 'Version', value = V},
                      #xmlAttribute{name = 'Destination', value = Dest}],
        content = [
            #xmlElement{name = 'saml:Issuer', content = [#xmlText{value = Issuer}]},
            #xmlElement{name = 'samlp:Status', content = [
                    #xmlElement{name = 'samlp:StatusCode', content = [
                        #xmlText{value = rev_status_code_map(Status)}]}]}
        ]
    });

  to_xml(#esaml_sp_metadata{org = #esaml_org{name = OrgName, displayname = OrgDisplayName,
                                             url = OrgUrl },
                         tech = #esaml_contact{name = TechName, email = TechEmail},
                         signed_requests = SignReq, signed_assertions = SignAss,
                         certificate = CertBin, cert_chain = CertChain, entity_id = EntityID,
                         consumer_location = ConsumerLoc,
                         logout_location = SLOLoc
                         }) ->

      Ns = #xmlNamespace{nodes = [{"md", 'urn:oasis:names:tc:SAML:2.0:metadata'},
                                  {"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'},
                                  {"dsig", 'http://www.w3.org/2000/09/xmldsig#'}]},

      KeyDescriptorElems = case CertBin of
          undefined -> [];
          C when is_binary(C) -> [
              #xmlElement{name = 'md:KeyDescriptor',
                  attributes = [#xmlAttribute{name = 'use', value = "signing"}],
                  content = [#xmlElement{name = 'dsig:KeyInfo',
                      content = [#xmlElement{name = 'dsig:X509Data',
                          content =
                                  [#xmlElement{name = 'dsig:X509Certificate',
                              content = [#xmlText{value = base64:encode_to_string(CertBin)}]} |
                                  [#xmlElement{name = 'dsig:X509Certificate',
                              content = [#xmlText{value = base64:encode_to_string(CertChainBin)}]} || CertChainBin <- CertChain]]}]}]},

              #xmlElement{name = 'md:KeyDescriptor',
                  attributes = [#xmlAttribute{name = 'use', value = "encryption"}],
                  content = [#xmlElement{name = 'dsig:KeyInfo',
                      content = [#xmlElement{name = 'dsig:X509Data',
                          content =
                                  [#xmlElement{name = 'dsig:X509Certificate',
                              content = [#xmlText{value = base64:encode_to_string(CertBin)}]} |
                                  [#xmlElement{name = 'dsig:X509Certificate',
                              content = [#xmlText{value = base64:encode_to_string(CertChainBin)}]} || CertChainBin <- CertChain]]}]}]}

          ]
      end,

      SingleLogoutServiceElems = case SLOLoc of
          undefined -> [];
          _ -> [
              #xmlElement{name = 'md:SingleLogoutService',
                  attributes = [#xmlAttribute{name = 'Binding', value = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"},
                                #xmlAttribute{name = 'Location', value = SLOLoc}]},
              #xmlElement{name = 'md:SingleLogoutService',
                  attributes = [#xmlAttribute{name = 'Binding', value = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"},
                                #xmlAttribute{name = 'Location', value = SLOLoc}]}
          ]
      end,

      AssertionConsumerServiceElems = [
          #xmlElement{name = 'md:AssertionConsumerService',
              attributes = [#xmlAttribute{name = 'isDefault', value = "true"},
                            #xmlAttribute{name = 'index', value = "0"},
                            #xmlAttribute{name = 'Binding', value = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"},
                            #xmlAttribute{name = 'Location', value = ConsumerLoc}]},
          #xmlElement{name = 'md:AssertionConsumerService',
              attributes = [#xmlAttribute{name = 'index', value = "1"},
                            #xmlAttribute{name = 'Binding', value = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"},
                            #xmlAttribute{name = 'Location', value = ConsumerLoc}]}
      ],

      OrganizationElem = #xmlElement{name = 'md:Organization',
          content =
              lang_elems(#xmlElement{name = 'md:OrganizationName'}, OrgName) ++
              lang_elems(#xmlElement{name = 'md:OrganizationDisplayName'}, OrgDisplayName) ++
              lang_elems(#xmlElement{name = 'md:OrganizationURL'}, OrgUrl)
      },

      ContactElem = #xmlElement{name = 'md:ContactPerson',
          attributes = [#xmlAttribute{name = 'contactType', value = "technical"}],
          content = [
              #xmlElement{name = 'md:SurName', content = [#xmlText{value = TechName}]},
              #xmlElement{name = 'md:EmailAddress', content = [#xmlText{value = TechEmail}]}
          ]
      },

      SPSSODescriptorElem = #xmlElement{name = 'md:SPSSODescriptor',
          attributes = [#xmlAttribute{name = 'protocolSupportEnumeration', value = "urn:oasis:names:tc:SAML:2.0:protocol"},
                        #xmlAttribute{name = 'AuthnRequestsSigned', value = atom_to_list(SignReq)},
                        #xmlAttribute{name = 'WantAssertionsSigned', value = atom_to_list(SignAss)}],
          content = KeyDescriptorElems ++ SingleLogoutServiceElems ++ AssertionConsumerServiceElems
      },

      esaml_util:build_nsinfo(Ns, #xmlElement{
          name = 'md:EntityDescriptor',
          attributes = [
              #xmlAttribute{name = 'xmlns:md', value = atom_to_list(proplists:get_value("md", Ns#xmlNamespace.nodes))},
              #xmlAttribute{name = 'xmlns:saml', value = atom_to_list(proplists:get_value("saml", Ns#xmlNamespace.nodes))},
              #xmlAttribute{name = 'xmlns:dsig', value = atom_to_list(proplists:get_value("dsig", Ns#xmlNamespace.nodes))},
              #xmlAttribute{name = 'entityID', value = EntityID}
          ], content = [
              SPSSODescriptorElem,
              OrganizationElem,
              ContactElem
          ]
      });

to_xml(_) -> error("unknown record").


-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

decode_response_test() ->
    {Doc, _} = xmerl_scan:string("<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Version=\"2.0\" IssueInstant=\"2013-01-01T01:01:01Z\" Destination=\"foo\"></samlp:Response>", [{namespace_conformant, true}]),
    Resp = decode_response(Doc),
    ?assertMatch({ok, #esaml_response{issue_instant = "2013-01-01T01:01:01Z", destination = "foo", status = unknown}}, Resp).

decode_response_no_version_test() ->
    {Doc, _} = xmerl_scan:string("<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" IssueInstant=\"2013-01-01T01:01:01Z\" Destination=\"foo\"></samlp:Response>", [{namespace_conformant, true}]),
    Resp = decode_response(Doc),
    {error, bad_version} = Resp.

decode_response_no_issue_instant_test() ->
    {Doc, _} = xmerl_scan:string("<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Version=\"2.0\" Destination=\"foo\"></samlp:Response>", [{namespace_conformant, true}]),
    Resp = decode_response(Doc),
    {error, bad_response} = Resp.

decode_response_destination_optional_test() ->
    {Doc, _} = xmerl_scan:string("<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Version=\"2.0\" IssueInstant=\"2013-01-01T01:01:01Z\"></samlp:Response>", [{namespace_conformant, true}]),
    Resp = decode_response(Doc),
    {ok, #esaml_response{issue_instant = "2013-01-01T01:01:01Z", status = unknown}} = Resp.

decode_response_status_test() ->
    {Doc, _} = xmerl_scan:string("<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Version=\"2.0\" IssueInstant=\"2013-01-01T01:01:01Z\"><saml:Issuer>foo</saml:Issuer><samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\" /></samlp:Status></samlp:Response>", [{namespace_conformant, true}]),
    Resp = decode_response(Doc),
    {ok, #esaml_response{issue_instant = "2013-01-01T01:01:01Z", status = success, issuer = "foo"}} = Resp.

decode_response_bad_assertion_test() ->
    {Doc, _} = xmerl_scan:string("<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Version=\"2.0\" IssueInstant=\"2013-01-01T01:01:01Z\"><saml:Issuer>foo</saml:Issuer><samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\" /></samlp:Status><saml:Assertion></saml:Assertion></samlp:Response>", [{namespace_conformant, true}]),
    Resp = decode_response(Doc),
    {error, bad_version} = Resp.

decode_assertion_no_recipient_test() ->
    {Doc, _} = xmerl_scan:string("<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Version=\"2.0\" IssueInstant=\"2013-01-01T01:01:01Z\"><saml:Issuer>foo</saml:Issuer><samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\" /></samlp:Status><saml:Assertion Version=\"2.0\" IssueInstant=\"test\"><saml:Issuer>foo</saml:Issuer><saml:Subject><saml:NameID>foobar</saml:NameID><saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\" /></saml:Subject></saml:Assertion></samlp:Response>", [{namespace_conformant, true}]),
    Resp = decode_response(Doc),
    {error, bad_recipient} = Resp.

decode_assertion_test() ->
    {Doc, _} = xmerl_scan:string("<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Version=\"2.0\" IssueInstant=\"2013-01-01T01:01:01Z\"><saml:Issuer>foo</saml:Issuer><samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\" /></samlp:Status><saml:Assertion Version=\"2.0\" IssueInstant=\"test\"><saml:Issuer>foo</saml:Issuer><saml:Subject><saml:NameID>foobar</saml:NameID><saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"><saml:SubjectConfirmationData Recipient=\"foobar123\" /></saml:SubjectConfirmation></saml:Subject></saml:Assertion></samlp:Response>", [{namespace_conformant, true}]),
    Resp = decode_response(Doc),
    {ok, #esaml_response{issue_instant = "2013-01-01T01:01:01Z", issuer = "foo", status = success, assertion = #esaml_assertion{issue_instant = "test", issuer = "foo", recipient = "foobar123", subject = #esaml_subject{name = "foobar", confirmation_method = bearer}}}} = Resp.

decode_conditions_test() ->
    {Doc, _} = xmerl_scan:string("<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Version=\"2.0\" IssueInstant=\"2013-01-01T01:01:01Z\"><saml:Issuer>foo</saml:Issuer><samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\" /></samlp:Status><saml:Assertion Version=\"2.0\" IssueInstant=\"test\"><saml:Issuer>foo</saml:Issuer><saml:Subject><saml:NameID>foobar</saml:NameID><saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"><saml:SubjectConfirmationData Recipient=\"foobar123\" /></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore=\"before\" NotOnOrAfter=\"notafter\"><saml:AudienceRestriction><saml:Audience>foobaraudience</saml:Audience></saml:AudienceRestriction></saml:Conditions></saml:Assertion></samlp:Response>", [{namespace_conformant, true}]),
    Resp = decode_response(Doc),
    {ok, #esaml_response{assertion = #esaml_assertion{conditions = Conds}}} = Resp,
    [{audience, "foobaraudience"}, {not_before, "before"}, {not_on_or_after, "notafter"}] = lists:sort(Conds).

decode_attributes_test() ->
    {Doc, _} = xmerl_scan:string("<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Version=\"2.0\" IssueInstant=\"test\"><saml:Subject><saml:NameID>foobar</saml:NameID><saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"><saml:SubjectConfirmationData Recipient=\"foobar123\" /></saml:SubjectConfirmation></saml:Subject><saml:AttributeStatement><saml:Attribute Name=\"urn:oid:0.9.2342.19200300.100.1.3\"><saml:AttributeValue>test@test.com</saml:AttributeValue></saml:Attribute><saml:Attribute Name=\"foo\"><saml:AttributeValue>george</saml:AttributeValue><saml:AttributeValue>bar</saml:AttributeValue></saml:Attribute><saml:Attribute Name=\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress\"><saml:AttributeValue>test@test.com</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>", [{namespace_conformant, true}]),
    Assertion = decode_assertion(Doc),
    {ok, #esaml_assertion{attributes = Attrs}} = Assertion,
    [{emailaddress, "test@test.com"}, {foo, ["george", "bar"]}, {mail, "test@test.com"}] = lists:sort(Attrs).

decode_solicited_in_response_to_test() ->
    {Doc, _} = xmerl_scan:string("<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Version=\"2.0\" IssueInstant=\"2013-01-01T01:01:01Z\"><saml:Issuer>foo</saml:Issuer><samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\" /></samlp:Status><saml:Assertion Version=\"2.0\" IssueInstant=\"test\"><saml:Issuer>foo</saml:Issuer><saml:Subject><saml:NameID>foobar</saml:NameID><saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"><saml:SubjectConfirmationData Recipient=\"foobar123\" InResponseTo=\"_1234567890\" /></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore=\"before\" NotOnOrAfter=\"notafter\"><saml:AudienceRestriction><saml:Audience>foobaraudience</saml:Audience></saml:AudienceRestriction></saml:Conditions></saml:Assertion></samlp:Response>", [{namespace_conformant, true}]),
    Resp = decode_response(Doc),
    {ok, #esaml_response{assertion = #esaml_assertion{subject = #esaml_subject{in_response_to = ReqId}}}} = Resp,
    "_1234567890" = ReqId.

decode_unsolicited_in_response_to_test() ->
    {Doc, _} = xmerl_scan:string("<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Version=\"2.0\" IssueInstant=\"2013-01-01T01:01:01Z\"><saml:Issuer>foo</saml:Issuer><samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\" /></samlp:Status><saml:Assertion Version=\"2.0\" IssueInstant=\"test\"><saml:Issuer>foo</saml:Issuer><saml:Subject><saml:NameID>foobar</saml:NameID><saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"><saml:SubjectConfirmationData Recipient=\"foobar123\" /></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore=\"before\" NotOnOrAfter=\"notafter\"><saml:AudienceRestriction><saml:Audience>foobaraudience</saml:Audience></saml:AudienceRestriction></saml:Conditions></saml:Assertion></samlp:Response>", [{namespace_conformant, true}]),
    Resp = decode_response(Doc),
    {ok, #esaml_response{assertion = #esaml_assertion{subject = #esaml_subject{in_response_to = ReqId}}}} = Resp,
    "" = ReqId.

validate_assertion_test() ->
    Now = erlang:localtime_to_universaltime(erlang:localtime()),
    DeathSecs = calendar:datetime_to_gregorian_seconds(Now) + 1,
    Death = esaml_util:datetime_to_saml(calendar:gregorian_seconds_to_datetime(DeathSecs)),

    Ns = #xmlNamespace{nodes = [{"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'}]},

    E1 = esaml_util:build_nsinfo(Ns, #xmlElement{name = 'saml:Assertion',
        attributes = [#xmlAttribute{name = 'xmlns:saml', value = "urn:oasis:names:tc:SAML:2.0:assertion"}, #xmlAttribute{name = 'Version', value = "2.0"}, #xmlAttribute{name = 'IssueInstant', value = "now"}],
        content = [
            #xmlElement{name = 'saml:Subject', content = [
                #xmlElement{name = 'saml:SubjectConfirmation', content = [
                    #xmlElement{name = 'saml:SubjectConfirmationData',
                        attributes = [#xmlAttribute{name = 'Recipient', value = "foobar"},
                                      #xmlAttribute{name = 'NotOnOrAfter', value = Death}]
                    } ]} ]},
            #xmlElement{name = 'saml:Conditions', content = [
                #xmlElement{name = 'saml:AudienceRestriction', content = [
                    #xmlElement{name = 'saml:Audience', content = [#xmlText{value = "foo"}]}] }] } ]
    }),
    {ok, Assertion} = validate_assertion(E1, "foobar", "foo"),
    #esaml_assertion{issue_instant = "now", recipient = "foobar", subject = #esaml_subject{notonorafter = Death}, conditions = [{audience, "foo"}]} = Assertion,
    {error, bad_recipient} = validate_assertion(E1, "foo", "something"),
    {error, bad_audience} = validate_assertion(E1, "foobar", "something"),

    E2 = esaml_util:build_nsinfo(Ns, #xmlElement{name = 'saml:Assertion',
        attributes = [#xmlAttribute{name = 'xmlns:saml', value = "urn:oasis:names:tc:SAML:2.0:assertion"}, #xmlAttribute{name = 'Version', value = "2.0"}, #xmlAttribute{name = 'IssueInstant', value = "now"}],
        content = [
            #xmlElement{name = 'saml:Subject', content = [
                #xmlElement{name = 'saml:SubjectConfirmation', content = [ ]} ]},
            #xmlElement{name = 'saml:Conditions', content = [
                #xmlElement{name = 'saml:AudienceRestriction', content = [
                    #xmlElement{name = 'saml:Audience', content = [#xmlText{value = "foo"}]}] }] } ]
    }),
    {error, bad_recipient} = validate_assertion(E2, "", "").

validate_stale_assertion_test() ->
    Ns = #xmlNamespace{nodes = [{"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'}]},
    OldStamp = esaml_util:datetime_to_saml({{1990,1,1}, {1,1,1}}),
    E1 = esaml_util:build_nsinfo(Ns, #xmlElement{name = 'saml:Assertion',
        attributes = [#xmlAttribute{name = 'xmlns:saml', value = "urn:oasis:names:tc:SAML:2.0:assertion"}, #xmlAttribute{name = 'Version', value = "2.0"}, #xmlAttribute{name = 'IssueInstant', value = "now"}],
        content = [
            #xmlElement{name = 'saml:Subject', content = [
                #xmlElement{name = 'saml:SubjectConfirmation', content = [
                    #xmlElement{name = 'saml:SubjectConfirmationData',
                        attributes = [#xmlAttribute{name = 'Recipient', value = "foobar"},
                                      #xmlAttribute{name = 'NotOnOrAfter', value = OldStamp}]
                    } ]} ]} ]
    }),
    {error, stale_assertion} = validate_assertion(E1, "foobar", "foo").


decode_idp_metadata_test() ->
    {Doc, _} = xmerl_scan:string("<?xml version=\"1.0\"?> <EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"https://idp/saml/metadata/entityid\"> <IDPSSODescriptor xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"> <KeyDescriptor use=\"signing\"> <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"> <ds:X509Data> <ds:X509Certificate>MIID3zCCAsegAwIBAgIUPF5Gco8WLkvOlY7cfozVjTNrzGQwDQYJKoZIhvcNAQEFBQAwRjERMA8GA1UECgwIU2t5VW5Cb3gxFTATBgNVBAsMDE9uZUxvZ2luIElkUDEa MBgGA1UEAwwRT25lTG9naW4gQWNjb3VudCAwHhcNMTkwODAxMTIxOTEwWhcNMjQwODAxMTIxOTEwWjBGMREwDwYDVQQKDAhTa3lVbkJveDEVMBMGA1UECwwMT25lTG9n aW4gSWRQMRowGAYDVQQDDBFPbmVMb2dpbiBBY2NvdW50IDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAN5Qi6ydpygTc4509duHQKfY8+aiX6CvOF17ELlR Pb5GqG2YPGDZyxncFG+TQBUi68BrxPGWoquCqjs/WIc8nFnaAnk8Av3NfC4iKr+cTQMfZflu7zKnmdBgi04/RripoGk7RWpQML7HUk4YvyRJZI2S7m/EsTfHVh4Wu8bu QCRbYEd5KS77090uj8gakHQ014vzIoqWdOginDoSc4T+WgQ/2v+y6FngrwJ8IeocKwN3ulNVoObFCTzHkdEtCNhzYmqBC36vqPQ3XGN8n8xZYOOQKsE1F2NclEfF2rgB jLrkdApTRDwhHfxlGoZYrZOQ8MkIWnflGuuUqQ1gzpjyA+MCAwEAAaOBxDCBwTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBRokBVgvKom+1vh/8ue5HtLoO5olTCBgQYD VR0jBHoweIAUaJAVYLyqJvtb4f/LnuR7S6DuaJWhSqRIMEYxETAPBgNVBAoMCFNreVVuQm94MRUwEwYDVQQLDAxPbmVMb2dpbiBJZFAxGjAYBgNVBAMMEU9uZUxvZ2lu IEFjY291bnQgghQ8XkZyjxYuS86Vjtx+jNWNM2vMZDAOBgNVHQ8BAf8EBAMCB4AwDQYJKoZIhvcNAQEFBQADggEBAKGvio8CegS83/U+obggwPTFFnYBj5czDZp9t8b3 CWHItmSGGDJKVKOQfK5avQVR6fGDg7zM28FbldZ7JhEbZhC36M/pZ72yxTiwcPfStoOEb/8zgmfjFTfuWVy4jSTfqLGTq/DCQa7H2y4Zk9rq9FccWgeY+GeSDwTf4pme SNlzyEUTzJMe97R1VSX4UIbJyWK71yd+QZWShiDIqeFEVaSKDQzRPQdyZinXmp9JIjqKTTxf7a8qZYmGpQh0ZyDroM993GU8bFMKMxWplEZPGbh+SKoydyQ3Y+1zGB73 WUeQ9jRLx2fCguGFgi9T89FW1/AvPqcSMPluPVBcmoSSZHo=</ds:X509Certificate> </ds:X509Data> </ds:KeyInfo> </KeyDescriptor><SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://idp/trust/saml2/http-redirect/slo/968046\"/> <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat> <SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://idp/trust/saml2/http-redirect/sso/entityid\"/> <SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://idp/trust/saml2/http-post/sso/entityid\"/> <SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:SOAP\" Location=\"https://idp/trust/saml2/soap/sso/entityid\"/> </IDPSSODescriptor> </EntityDescriptor>", [{namespace_conformant, true}]),
    {ok, IDPMetadata} = decode_idp_metadata(Doc),
    ?debugVal(IDPMetadata#esaml_idp_metadata.certificates),

    ?assertMatch(#esaml_idp_metadata{
        org = #esaml_org{},
        tech = #esaml_contact{},
        login_location = "https://idp/trust/saml2/http-post/sso/entityid",
        certificates = [
            <<48,130,3,223,48,130,2,199,160,3,2,1,2,2,20,60,94,70,114,
                143,22,46,75,206,149,142,220,126,140,213,141,51,107,204,
                100,48,13,6,9,42,134,72,134,247,13,1,1,5,5,0,48,70,49,
                17,48,15,6,3,85,4,10,12,8,83,107,121,85,110,66,111,120,
                49,21,48,19,6,3,85,4,11,12,12,79,110,101,76,111,103,105,
                110,32,73,100,80,49,26,48,24,6,3,85,4,3,12,17,79,110,
                101,76,111,103,105,110,32,65,99,99,111,117,110,116,32,
                48,30,23,13,49,57,48,56,48,49,49,50,49,57,49,48,90,23,
                13,50,52,48,56,48,49,49,50,49,57,49,48,90,48,70,49,17,
                48,15,6,3,85,4,10,12,8,83,107,121,85,110,66,111,120,49,
                21,48,19,6,3,85,4,11,12,12,79,110,101,76,111,103,105,
                110,32,73,100,80,49,26,48,24,6,3,85,4,3,12,17,79,110,
                101,76,111,103,105,110,32,65,99,99,111,117,110,116,32,
                48,130,1,34,48,13,6,9,42,134,72,134,247,13,1,1,1,5,0,3,
                130,1,15,0,48,130,1,10,2,130,1,1,0,222,80,139,172,157,
                167,40,19,115,142,116,245,219,135,64,167,216,243,230,
                162,95,160,175,56,93,123,16,185,81,61,190,70,168,109,
                152,60,96,217,203,25,220,20,111,147,64,21,34,235,192,
                107,196,241,150,162,171,130,170,59,63,88,135,60,156,89,
                218,2,121,60,2,253,205,124,46,34,42,191,156,77,3,31,101,
                249,110,239,50,167,153,208,96,139,78,63,70,184,169,160,
                105,59,69,106,80,48,190,199,82,78,24,191,36,73,100,141,
                146,238,111,196,177,55,199,86,30,22,187,198,238,64,36,
                91,96,71,121,41,46,251,211,221,46,143,200,26,144,116,52,
                215,139,243,34,138,150,116,232,34,156,58,18,115,132,254,
                90,4,63,218,255,178,232,89,224,175,2,124,33,234,28,43,3,
                119,186,83,85,160,230,197,9,60,199,145,209,45,8,216,115,
                98,106,129,11,126,175,168,244,55,92,99,124,159,204,89,
                96,227,144,42,193,53,23,99,92,148,71,197,218,184,1,140,
                186,228,116,10,83,68,60,33,29,252,101,26,134,88,173,147,
                144,240,201,8,90,119,229,26,235,148,169,13,96,206,152,
                242,3,227,2,3,1,0,1,163,129,196,48,129,193,48,12,6,3,85,
                29,19,1,1,255,4,2,48,0,48,29,6,3,85,29,14,4,22,4,20,104,
                144,21,96,188,170,38,251,91,225,255,203,158,228,123,75,
                160,238,104,149,48,129,129,6,3,85,29,35,4,122,48,120,
                128,20,104,144,21,96,188,170,38,251,91,225,255,203,158,
                228,123,75,160,238,104,149,161,74,164,72,48,70,49,17,48,
                15,6,3,85,4,10,12,8,83,107,121,85,110,66,111,120,49,21,
                48,19,6,3,85,4,11,12,12,79,110,101,76,111,103,105,110,
                32,73,100,80,49,26,48,24,6,3,85,4,3,12,17,79,110,101,76,
                111,103,105,110,32,65,99,99,111,117,110,116,32,130,20,
                60,94,70,114,143,22,46,75,206,149,142,220,126,140,213,
                141,51,107,204,100,48,14,6,3,85,29,15,1,1,255,4,4,3,2,7,
                128,48,13,6,9,42,134,72,134,247,13,1,1,5,5,0,3,130,1,1,
                0,161,175,138,143,2,122,4,188,223,245,62,161,184,32,192,
                244,197,22,118,1,143,151,51,13,154,125,183,198,247,9,97,
                200,182,100,134,24,50,74,84,163,144,124,174,90,189,5,81,
                233,241,131,131,188,204,219,193,91,149,214,123,38,17,27,
                102,16,183,232,207,233,103,189,178,197,56,176,112,247,
                210,182,131,132,111,255,51,130,103,227,21,55,238,89,92,
                184,141,36,223,168,177,147,171,240,194,65,174,199,219,
                46,25,147,218,234,244,87,28,90,7,152,248,103,146,15,4,
                223,226,153,158,72,217,115,200,69,19,204,147,30,247,180,
                117,85,37,248,80,134,201,201,98,187,215,39,126,65,149,
                146,134,32,200,169,225,68,85,164,138,13,12,209,61,7,114,
                102,41,215,154,159,73,34,58,138,77,60,95,237,175,42,101,
                137,134,165,8,116,103,32,235,160,207,125,220,101,60,108,
                83,10,51,21,169,148,70,79,25,184,126,72,170,50,119,36,
                55,99,237,115,24,30,247,89,71,144,246,52,75,199,103,194,
                130,225,133,130,47,83,243,209,86,215,240,47,62,167,18,
                48,249,110,61,80,92,154,132,146,100,122>>]

    }, IDPMetadata).

decode_idp_metadata_multiple_certificates_test() ->
    {Doc, _} = xmerl_scan:string("<?xml version=\"1.0\"?> <EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"https://idp/saml/metadata/entityid\"> <IDPSSODescriptor xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"> <KeyDescriptor use=\"signing\"> <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"> <ds:X509Data> <ds:X509Certificate>MIID3zCCAsegAwIBAgIUPF5Gco8WLkvOlY7cfozVjTNrzGQwDQYJKoZIhvcNAQEFBQAwRjERMA8GA1UECgwIU2t5VW5Cb3gxFTATBgNVBAsMDE9uZUxvZ2luIElkUDEa MBgGA1UEAwwRT25lTG9naW4gQWNjb3VudCAwHhcNMTkwODAxMTIxOTEwWhcNMjQwODAxMTIxOTEwWjBGMREwDwYDVQQKDAhTa3lVbkJveDEVMBMGA1UECwwMT25lTG9n aW4gSWRQMRowGAYDVQQDDBFPbmVMb2dpbiBBY2NvdW50IDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAN5Qi6ydpygTc4509duHQKfY8+aiX6CvOF17ELlR Pb5GqG2YPGDZyxncFG+TQBUi68BrxPGWoquCqjs/WIc8nFnaAnk8Av3NfC4iKr+cTQMfZflu7zKnmdBgi04/RripoGk7RWpQML7HUk4YvyRJZI2S7m/EsTfHVh4Wu8bu QCRbYEd5KS77090uj8gakHQ014vzIoqWdOginDoSc4T+WgQ/2v+y6FngrwJ8IeocKwN3ulNVoObFCTzHkdEtCNhzYmqBC36vqPQ3XGN8n8xZYOOQKsE1F2NclEfF2rgB jLrkdApTRDwhHfxlGoZYrZOQ8MkIWnflGuuUqQ1gzpjyA+MCAwEAAaOBxDCBwTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBRokBVgvKom+1vh/8ue5HtLoO5olTCBgQYD VR0jBHoweIAUaJAVYLyqJvtb4f/LnuR7S6DuaJWhSqRIMEYxETAPBgNVBAoMCFNreVVuQm94MRUwEwYDVQQLDAxPbmVMb2dpbiBJZFAxGjAYBgNVBAMMEU9uZUxvZ2lu IEFjY291bnQgghQ8XkZyjxYuS86Vjtx+jNWNM2vMZDAOBgNVHQ8BAf8EBAMCB4AwDQYJKoZIhvcNAQEFBQADggEBAKGvio8CegS83/U+obggwPTFFnYBj5czDZp9t8b3 CWHItmSGGDJKVKOQfK5avQVR6fGDg7zM28FbldZ7JhEbZhC36M/pZ72yxTiwcPfStoOEb/8zgmfjFTfuWVy4jSTfqLGTq/DCQa7H2y4Zk9rq9FccWgeY+GeSDwTf4pme SNlzyEUTzJMe97R1VSX4UIbJyWK71yd+QZWShiDIqeFEVaSKDQzRPQdyZinXmp9JIjqKTTxf7a8qZYmGpQh0ZyDroM993GU8bFMKMxWplEZPGbh+SKoydyQ3Y+1zGB73 WUeQ9jRLx2fCguGFgi9T89FW1/AvPqcSMPluPVBcmoSSZHo=</ds:X509Certificate> </ds:X509Data> </ds:KeyInfo> </KeyDescriptor> <KeyDescriptor use=\"signing\"> <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"> <ds:X509Data> <ds:X509Certificate>op8w6U7cFF6Uepym8ovgN+F6nCXfAq9Bl13Fcz7qJKVbxDP3Je4ZgbH8lJAwIVEHrwAkIrghA4dPxUiNzuEQl2e4UJ4y7emrpQV7zyBAG2pns8sE0F+htUSywMT/1ZKWAT7Kvuy3xDZ7ENe+oQN3dZCs1GCV4/8yFWiLOB3P+DieuBvfwKYL7DS9HEuGR5CxXAjvddbSg6fyizR67+b8mA==</ds:X509Certificate> </ds:X509Data> </ds:KeyInfo> </KeyDescriptor> <SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://idp/trust/saml2/http-redirect/slo/968046\"/> <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat> <SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://idp/trust/saml2/http-redirect/sso/entityid\"/> <SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://idp/trust/saml2/http-post/sso/entityid\"/> <SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:SOAP\" Location=\"https://idp/trust/saml2/soap/sso/entityid\"/> </IDPSSODescriptor> </EntityDescriptor>", [{namespace_conformant, true}]),
    {ok, IDPMetadata} = decode_idp_metadata(Doc),

    ?debugVal(IDPMetadata#esaml_idp_metadata.certificates),

    ?assertMatch(#esaml_idp_metadata{
        org = #esaml_org{},
        tech = #esaml_contact{},
        login_location = "https://idp/trust/saml2/http-post/sso/entityid",
        certificates = [
            <<48,130,3,223,48,130,2,199,160,3,2,1,2,2,20,60,94,70,114,
            143,22,46,75,206,149,142,220,126,140,213,141,51,107,204,
            100,48,13,6,9,42,134,72,134,247,13,1,1,5,5,0,48,70,49,
            17,48,15,6,3,85,4,10,12,8,83,107,121,85,110,66,111,120,
            49,21,48,19,6,3,85,4,11,12,12,79,110,101,76,111,103,105,
            110,32,73,100,80,49,26,48,24,6,3,85,4,3,12,17,79,110,
            101,76,111,103,105,110,32,65,99,99,111,117,110,116,32,
            48,30,23,13,49,57,48,56,48,49,49,50,49,57,49,48,90,23,
            13,50,52,48,56,48,49,49,50,49,57,49,48,90,48,70,49,17,
            48,15,6,3,85,4,10,12,8,83,107,121,85,110,66,111,120,49,
            21,48,19,6,3,85,4,11,12,12,79,110,101,76,111,103,105,
            110,32,73,100,80,49,26,48,24,6,3,85,4,3,12,17,79,110,
            101,76,111,103,105,110,32,65,99,99,111,117,110,116,32,
            48,130,1,34,48,13,6,9,42,134,72,134,247,13,1,1,1,5,0,3,
            130,1,15,0,48,130,1,10,2,130,1,1,0,222,80,139,172,157,
            167,40,19,115,142,116,245,219,135,64,167,216,243,230,
            162,95,160,175,56,93,123,16,185,81,61,190,70,168,109,
            152,60,96,217,203,25,220,20,111,147,64,21,34,235,192,
            107,196,241,150,162,171,130,170,59,63,88,135,60,156,89,
            218,2,121,60,2,253,205,124,46,34,42,191,156,77,3,31,101,
            249,110,239,50,167,153,208,96,139,78,63,70,184,169,160,
            105,59,69,106,80,48,190,199,82,78,24,191,36,73,100,141,
            146,238,111,196,177,55,199,86,30,22,187,198,238,64,36,
            91,96,71,121,41,46,251,211,221,46,143,200,26,144,116,52,
            215,139,243,34,138,150,116,232,34,156,58,18,115,132,254,
            90,4,63,218,255,178,232,89,224,175,2,124,33,234,28,43,3,
            119,186,83,85,160,230,197,9,60,199,145,209,45,8,216,115,
            98,106,129,11,126,175,168,244,55,92,99,124,159,204,89,
            96,227,144,42,193,53,23,99,92,148,71,197,218,184,1,140,
            186,228,116,10,83,68,60,33,29,252,101,26,134,88,173,147,
            144,240,201,8,90,119,229,26,235,148,169,13,96,206,152,
            242,3,227,2,3,1,0,1,163,129,196,48,129,193,48,12,6,3,85,
            29,19,1,1,255,4,2,48,0,48,29,6,3,85,29,14,4,22,4,20,104,
            144,21,96,188,170,38,251,91,225,255,203,158,228,123,75,
            160,238,104,149,48,129,129,6,3,85,29,35,4,122,48,120,
            128,20,104,144,21,96,188,170,38,251,91,225,255,203,158,
            228,123,75,160,238,104,149,161,74,164,72,48,70,49,17,48,
            15,6,3,85,4,10,12,8,83,107,121,85,110,66,111,120,49,21,
            48,19,6,3,85,4,11,12,12,79,110,101,76,111,103,105,110,
            32,73,100,80,49,26,48,24,6,3,85,4,3,12,17,79,110,101,76,
            111,103,105,110,32,65,99,99,111,117,110,116,32,130,20,
            60,94,70,114,143,22,46,75,206,149,142,220,126,140,213,
            141,51,107,204,100,48,14,6,3,85,29,15,1,1,255,4,4,3,2,7,
            128,48,13,6,9,42,134,72,134,247,13,1,1,5,5,0,3,130,1,1,
            0,161,175,138,143,2,122,4,188,223,245,62,161,184,32,192,
            244,197,22,118,1,143,151,51,13,154,125,183,198,247,9,97,
            200,182,100,134,24,50,74,84,163,144,124,174,90,189,5,81,
            233,241,131,131,188,204,219,193,91,149,214,123,38,17,27,
            102,16,183,232,207,233,103,189,178,197,56,176,112,247,
            210,182,131,132,111,255,51,130,103,227,21,55,238,89,92,
            184,141,36,223,168,177,147,171,240,194,65,174,199,219,
            46,25,147,218,234,244,87,28,90,7,152,248,103,146,15,4,
            223,226,153,158,72,217,115,200,69,19,204,147,30,247,180,
            117,85,37,248,80,134,201,201,98,187,215,39,126,65,149,
            146,134,32,200,169,225,68,85,164,138,13,12,209,61,7,114,
            102,41,215,154,159,73,34,58,138,77,60,95,237,175,42,101,
            137,134,165,8,116,103,32,235,160,207,125,220,101,60,108,
            83,10,51,21,169,148,70,79,25,184,126,72,170,50,119,36,
            55,99,237,115,24,30,247,89,71,144,246,52,75,199,103,194,
            130,225,133,130,47,83,243,209,86,215,240,47,62,167,18,
            48,249,110,61,80,92,154,132,146,100,122>>,
            <<162,159,48,233,78,220,20,94,148,122,156,166,242,139,224,
            55,225,122,156,37,223,2,175,65,151,93,197,115,62,234,36,165,
            91,196,51,247,37,238,25,129,177,252,148,144,48,33,
            81,7,175,0,36,34,184,33,3,135,79,197,72,141,206,225,16,
            151,103,184,80,158,50,237,233,171,165,5,123,207,32,64,
            27,106,103,179,203,4,208,95,161,181,68,178,192,196,255,
            213,146,150,1,62,202,190,236,183,196,54,123,16,215,190,
            161,3,119,117,144,172,212,96,149,227,255,50,21,104,139,
            56,29,207,248,56,158,184,27,223,192,166,11,236,52,189,
            28,75,134,71,144,177,92,8,239,117,214,210,131,167,242,
            139,52,122,239,230,252,152>>
    ]
    }, IDPMetadata).
-endif.
