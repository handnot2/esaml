-module(esaml_sp_test).

-include_lib("eunit/include/eunit.hrl").
-include_lib("xmerl/include/xmerl.hrl").
-include("esaml.hrl").


path(Name, Ext) ->
  "test/esaml_sp_" ++ Name ++ "." ++ Ext.


path(Ext) ->
  "test/esaml_sp." ++ Ext.


validate_assertion_test_() ->
  {setup,
    fun() ->
      {ok, Sup} = esaml:start(permanent, []),
      Sup
    end,
    fun(Sup) ->
     gen_server:stop(Sup)
    end,
    [
      {"inline key", fun() ->
        {Xml, SP} = build_sp("inline"),
        ?assertMatch({error,stale_assertion}, esaml_sp:validate_assertion(Xml, SP))
      end},
      {"local key", fun() ->
        {Xml, SP} = build_sp("local"),
        ?assertMatch({error,stale_assertion}, esaml_sp:validate_assertion(Xml, SP))
      end}
    ]
  }.

get_xml(Name) ->
  case file:read_file(path(Name, "xml")) of
    {ok, <<"<", _/binary>> = Text} ->
      ok;
    {ok, Encoded} ->
      Text = base64:decode(Encoded)
  end,
  {Xml, _} = xmerl_scan:string(binary_to_list(Text), [{namespace_conformant, true}]),
  Xml.

build_sp(Name) ->
  Xml = get_xml(Name),
  ConsumeUrl = "http://localhost:4000/saml/login",
  Recipient = "urn:f5156378-6d88-44b0-a38a-31219f1af162",
  PrivKey = esaml_util:load_private_key(path("key")),
  Cert = esaml_util:load_certificate(path("crt")),

  SP = esaml_sp:setup(#esaml_sp{
    entity_id = Recipient,
    key = PrivKey,
    certificate = Cert,
    idp_signs_assertions = false,
    idp_signs_envelopes = false,
    consume_uri = ConsumeUrl,
    metadata_uri = ConsumeUrl,
    org = #esaml_org{
        name = "Foo Bar",
        displayname = "Foo Bar",
        url = "http://some.hostname.com"
    },
    tech = #esaml_contact{
        name = "Foo Bar",
        email = "foo@bar.com"
    }
  }),

  {Xml, SP#esaml_sp{trusted_fingerprints = any}}.
