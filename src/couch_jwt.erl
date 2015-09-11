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

-module(couch_jwt).

-export([encode/3, decode/3]).

-type algorithm() :: binary().
-type json_object() :: {[{binary(), jiffy:json_value()}]}.

-spec encode(json_object(), binary(), algorithm()) -> binary().
encode(Payload, Key, <<"HS256">> = Algorithm) ->
    HeaderJson = jiffy:encode(
        {[{<<"typ">>, <<"JWT">>}, {<<"alg">>, Algorithm}]}),
    PayloadJson = jiffy:encode(Payload),
    Base64Header = mochiweb_base64url:encode(HeaderJson),
    Base64Payload = mochiweb_base64url:encode(PayloadJson),
    Data = <<Base64Header/binary,".",Base64Payload/binary>>,
    Signature = crypto:hmac(sha256, Key, Data),
    Base64Signature = mochiweb_base64url:encode(Signature),
    <<Data/binary,".",Base64Signature/binary>>.


-spec decode(binary(), binary(), algorithm()) ->
    {ok, json_object()} |
    {error, malformed_token | invalid_header | invalid_signature}.
decode(Jwt, Key, <<"HS256">> = _Algorithm) ->
    try
        [Base64Header, Rest] = binary:split(Jwt, <<".">>),
        [Base64Payload, Base64Signature] = binary:split(Rest, <<".">>),
        Header = jiffy:decode(mochiweb_base64url:decode(Base64Header)),
        case valid_header(Header) of
        false ->
            {error, invalid_header};
        true ->
            Payload = jiffy:decode(mochiweb_base64url:decode(Base64Payload)),
            Signature = mochiweb_base64url:decode(Base64Signature),
            SigningInput = <<Base64Header/binary,".",Base64Payload/binary>>,
            case crypto:hmac(sha256, Key, SigningInput) of
            Signature ->
                {ok, Payload};
            _ ->
                {error, invalid_signature}
            end
        end
    catch _:_ ->
        {error, malformed_token}
    end.

valid_header({HeaderProperties}) ->
    case couch_util:get_value(<<"typ">>, HeaderProperties) of
    <<"JWT">> ->
        case couch_util:get_value(<<"alg">>, HeaderProperties) of
        <<"HS256">> ->
            true;
        _ ->
            false
        end;
    _ ->
        false
    end.
