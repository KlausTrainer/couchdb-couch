% Licensed under the Apache License, Version 2.0 (the "License"); you may not
% use this file except in compliance with the License.  You may obtain a copy of
% the License at
%
%   http://www.apache.org/licenses/LICENSE-2.0
%
% Unless required by applicable law or agreed to in writing, software
% distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
% WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
% License for the specific language governing permissions and limitations under
% the License.

-module(couch_httpd_jwt).

-include_lib("couch/include/couch_db.hrl").

-export([jwt_authentication_handler/1, jwt_authentication_handler/2,
    create_jwt/2]).

jwt_authentication_handler(Req) ->
    jwt_authentication_handler(Req, couch_auth_cache).

jwt_authentication_handler(#httpd{mochi_req=MochiReq} = Req, AuthModule) ->
    case MochiReq:get_header_value("authorization") of
    undefined ->
        Req;
    AuthHeader ->
        [Head | Tail] = re:split(AuthHeader, "\\s",
            [{parts, 2}, {return, list}]),
        case [string:to_lower(Head) | Tail] of
        ["bearer", Rest] ->
            Jwt = ?l2b(Rest),
            Secret = ?l2b(couch_httpd_auth:ensure_cookie_auth_secret()),
            case couch_jwt:decode(Jwt, Secret, <<"HS256">>) of
            {error, malformed_token} ->
                Reason = <<"Malformed Authorization header. ",
                           "The token format doesn't conform with RFC 7519.">>,
                throw({bad_request, Reason});
            {error, _Reason} ->
                Req;
            {ok, {PayloadProperties}} ->
                Name = couch_util:get_value(name_claim(), PayloadProperties,
                    null),
                Roles = couch_util:get_value(roles_claim(), PayloadProperties,
                    []),
                couch_log:debug("Successful JWT auth as: ~p", [Name]),
                Req#httpd{user_ctx=#user_ctx{name=Name, roles=Roles}}
            end;
        _ ->
            Req
        end
    end.

create_jwt(Name, UserProps) ->
    Iss = case ?l2b(config:get("vendor", "version", "")) of
    <<>> ->
        <<"Apache CouchDB">>;
    CouchVersion ->
        <<"Apache CouchDB ",CouchVersion/binary>>
    end,
    Iat = couch_httpd_auth:make_cookie_time(),
    Exp = Iat + config:get_integer("couch_httpd_auth", "timeout", 600),
    Rev = couch_util:get_value(<<"_rev">>, UserProps,
        ?l2b(couch_util:to_hex(couch_util:md5(term_to_binary(UserProps))))),
    Payload = {
        [
            {<<"iss">>, Iss},
            {name_claim(), Name},
            {<<"exp">>, Exp},
            {<<"iat">>, Iat},
            {roles_claim(), couch_util:get_value(<<"roles">>, UserProps, [])},
            {<<"_rev">>, Rev}
        ]
    },
    Secret = ?l2b(couch_httpd_auth:ensure_cookie_auth_secret()),
    couch_jwt:encode(Payload, Secret, <<"HS256">>).

validate_jwt_payload({PayloadProperties} = Payload, AuthModule) ->
    {ok, Payload}.

name_claim() ->
    ?l2b(config:get("couch_httpd_auth", "jwt_name_claim", "sub")).

roles_claim() ->
    ?l2b(config:get("couch_httpd_auth", "jwt_roles_claim", "roles")).
