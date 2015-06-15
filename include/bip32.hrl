% Copyright (c) 2015 <Matthew Branton>
% See LICENSE
%

-author('mbranton@emberfinancial.com').

% HD key format

-record(bip32_priv_key, {key, chain_code, depth, child_num, finger_print, network}).
-record(bip32_pub_key, {key, chain_code, depth, child_num, finger_print, network}).
