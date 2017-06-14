%% Copyright 2017, Travelping GmbH <info@travelping.com>

%% This program is free software; you can redistribute it and/or
%% modify it under the terms of the GNU General Public License
%% as published by the Free Software Foundation; either version
%% 2 of the License, or (at your option) any later version.

-module(integration_SUITE).

-compile(export_all).

-include_lib("common_test/include/ct.hrl").

%%%===================================================================
%%% API
%%%===================================================================

init_per_suite(Config) ->
    ok.

end_per_suite(_Config) ->
    ok.


all() ->
    [integration].

%%%===================================================================
%%% Tests
%%%===================================================================

%%--------------------------------------------------------------------
integration() ->
    [{doc, "Test that a complete erGW system works"}].
integration(_Config) ->
    %% do something here
    ok.
