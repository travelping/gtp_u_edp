%% Copyright 2017, Travelping GmbH <info@travelping.com>

%% This program is free software; you can redistribute it and/or
%% modify it under the terms of the GNU General Public License
%% as published by the Free Software Foundation; either version
%% 2 of the License, or (at your option) any later version.

-module(gtp_u_edp_metrics).

-compile({parse_transform, cut}).

-export([init/1,
	 measure_request/1,
	 measure_request_error/2,
	 measure_request_error/3]).

-include_lib("gtplib/include/gtp_packet.hrl").
-include("include/gtp_u_edp.hrl").

-define(EXO_PERF_OPTS, [
		        {time_span, 300 * 1000},  %% 5 min histogram

		        %% exometer spawns a process per historgram
		        %% the default exometer-`min_heap_size` for such a
		        %% process is about 40k words (320+ kbyte). this
		        %% results in measurable memory overhead per
		        %% histogram. we set `min_heap_size` to 233, as
		        %% described in the Erlang Efficiency Guide, see
		        %% http://erlang.org/doc/efficiency_guide/advanced.html#id71365
		        {min_heap_size, 233}]).
-define(GTP_U_MSGS, [echo_request, version_not_supported,
		      end_marker, g_pdu]).
-define(GTP_U_ERRS, [context_not_found,
		     invalid_payload,
		     send_failed
		    ]).

%% ===================================================================
%% API functions
%% ===================================================================

exo_hist_opts(echo_request) ->
    %% 1 hour might seem long, but we only send one echo request per 60 seconds
    [{time_span, 3600 * 1000}];
exo_hist_opts(_Type) ->
    %% 5 min histogram
    ?EXO_PERF_OPTS.

exo_reg_msg(Name, Version, Type) ->
    exometer:re_register([socket, 'gtp-u', Name, pt, Version, Type],
                         histogram, exo_hist_opts(Type)),
    exometer:re_register([socket, 'gtp-u', Name, rx, Version, Type], counter, []).

exo_reg_err(Name, Error) ->
    exometer:re_register([socket, 'gtp-u', Name, Error, pt],
                         histogram, exo_hist_opts(Error)),
    exometer:re_register([socket, 'gtp-u', Name, Error, count], counter, []).

init(Name) ->
    lists:foreach(exo_reg_msg(Name, v1, _), ?GTP_U_MSGS),
    lists:foreach(exo_reg_err(Name, _), ?GTP_U_ERRS),
    ok.

measure_request(#request{name = Name, arrival_ts = ArrivalTS,
				 msg = #gtp{version = Version, type = Type}}) ->
    measure_processing_time(Name, Version, Type, ArrivalTS).

measure_request_error(#request{name = Name, arrival_ts = ArrivalTS}, Error)
  when is_atom(Error) ->
    measure_request_error(Name, ArrivalTS, Error).

measure_request_error(Name, ArrivalTS, Error) ->
    measure_processing_time([socket, 'gtp-u', Name, Error, pt], ArrivalTS),
    exometer:update_or_create([socket, 'gtp-u', Name, Error, count],
			      1, counter, []).

measure_processing_time(DataPoint, ArrivalTS) ->
    Duration = erlang:convert_time_unit(erlang:monotonic_time() - ArrivalTS, native, microsecond),
    exometer:update(DataPoint, Duration).

measure_processing_time(Name, Version, Type, ArrivalTS) ->
    measure_processing_time([socket, 'gtp-u', Name, pt, Version, Type], ArrivalTS).
