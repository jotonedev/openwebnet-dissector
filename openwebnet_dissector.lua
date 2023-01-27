-- cmd aren't actually openwebnet commands, but are used to identify the type of message
local cmd = {
    [1] = "OPEN_SESSION",
    [2] = "HMAC",
    [3] = "NONCE",
    [4] = "PASSWORD",
    [5] = "ACK",
    [6] = "NACK",
    [7] = "NORMAL",
    [8] = "STATUS_REQUEST",
    [9] = "DIMENSION_REQUEST",
    [10] = "DIMENSION_WRITING"
}

local session = {
    [0] = "COMMAND_SESSION",
    [1] = "EVENT_SESSION"
}

local auth_type = {
    [1] = "SHA1",
    [2] = "SHA256"
}

-- from documentation
local who = {
    [0] = "Scenarios",
    [1] = "Lighting",
    [2] = "Automation",
    [3] = "Power Management",
    [4] = "Temperature Control",
    [5] = "Alarm",
    [6] = "VDES",
    [7] = "Video Door Entry System/multimedia",
    [9] = "Auxiliary",
    [13] = "Gateway Management",
    [14] = "Light+shutters actuators lock",
    [15] = "CEN commands",
    [16] = "Sound System/Audio",
    [17] = "MH200N scenarios",
    [18] = "Energy management",
    [22] = "Sound diffusion",
    [24] = "Lighting management",
    [25] = "CEN plus / scenarios plus / dry contacts",
    [1001] = "Automation diagnostic",
    [1004] = "Thermoregulation diagnostic",
    [1013] = "Device diagnostic"
}


local own = Proto("own", "OpenWebNet protocol")

local f = own.fields
f.msg = ProtoField.string("own.msg", "Message")
f.cmd = ProtoField.uint8("own.cmd", "Command", base.HEX, cmd)
f.session = ProtoField.uint8("own.session", "Session Type", base.DEC, session)
f.auth_type = ProtoField.uint8("own.auth_type", "Auth Type", base.DEC, auth_type)
f.nonce = ProtoField.uint16("own.nonce", "Nonce", base.DEC)
f.password = ProtoField.uint16("own.password", "Password", base.DEC)

f.who = ProtoField.uint16("own.who", "Who", base.DEC, who)
f.what = ProtoField.string("own.what", "What")
f.where = ProtoField.string("own.where", "Where")
f.dimension = ProtoField.string("own.dimension", "Dimension")

f.values = ProtoField.string("own.value", "Values")
f.value = ProtoField.string("own.value", "Value")
f.tag = ProtoField.uint8("own.tag", "Tag", base.DEC)
f.param = ProtoField.uint8("own.param", "Param", base.DEC)


function own.dissector(buffer, pkt_info, root_tree)
    if buffer:len() < 4 then return end

    pkt_info.cols.protocol = "OpenWebNet"
    main_tree = root_tree:add(own, buffer)
    
    local payload = buffer(0, buffer:len()):string()

    local prev_i = 0
    local i = 0
    while true do
        _, i = string.find(payload, "##", i+1)
        if i == nil then break end

        msg = buffer(prev_i, i-prev_i):string()
        prev_i = i
        msg_tree = main_tree:add(f.msg, msg)
        dissect_message(msg, pkt_info, msg_tree)
    end
end

function dissect_message(msg, pkt_info, main_tree)
    if m_open_session(msg) then
        main_tree:add(f.cmd, 1)

        local type = string.match(msg, "^[*]99[*](%d)##")
        main_tree:add(f.session, tonumber(type))
    elseif m_rqt_hmac(msg) then
        main_tree:add(f.cmd, 2)

        local type = string.match(msg, "^[*]98[*](%d)##")
        main_tree:add(f.auth_type, tonumber(type))
    elseif m_nonce(msg) then
        local nonce = string.match(msg, "%d+")

        if pkt_info.src_port == 20000 then
            main_tree:add(f.cmd, 3)
            main_tree:add(f.nonce, tonumber(nonce))
        else
            main_tree:add(f.cmd, 4)
            main_tree:add(f.password, tonumber(nonce))
        end        
    elseif m_ack(msg) then
        main_tree:add(f.cmd, 5)
    elseif m_nack(msg) then
        main_tree:add(f.cmd, 6)
    elseif m_norm(msg) then
        main_tree:add(f.cmd, 7)

        local t = parse_message(msg)
        main_tree:add(f.who, t[1])
        parse_what(t[2], main_tree)
        parse_where(t[3], main_tree)
    elseif m_sts(msg) then
        main_tree:add(f.cmd, 8)

        local t = parse_message(msg)
        main_tree:add(f.who, t[1])
        parse_where(t[3], main_tree)
    elseif m_dim_req(msg) then
        main_tree:add(f.cmd,9)
        local t = parse_message(msg)

        main_tree:add(f.who, t[1])
        parse_where(t[3], main_tree)
        main_tree:add(f.dimension, t[3])
    elseif m_dim_wtr(msg) then
        main_tree:add(f.cmd, 10)
        local t = parse_message(msg)

        main_tree:add(f.who, t[1])
        parse_where(t[3], main_tree)
        main_tree:add(f.dimension, t[3])
        parse_values(t, main_tree)
    end
end

function parse_values(table, tree)
    local field = ""
    for i, value in ipairs(table) do
        if i > 3 then
            field = field .. "*".. value
        end
    end

    local values = tree:add(f.values, field)
    for i, value in ipairs(table) do
        if i > 3 then
            values:add(f.value, value)
        end
    end
end


function parse_where(field, tree)
    local t = parse_params(field)
    local where_tree = tree:add(f.where, field)

    if t[1] ~= nil then
        where_tree:add(f.tag, t[1])
    end
    
    for i, value in ipairs(t) do
        if i ~= 1 then
            where_tree:add(f.param, value)
        end
    end
end

function parse_what(field, tree)
    local t = parse_params(field)
    local what_tree = tree:add(f.what, field)

    if t[1] ~= nil then
        what_tree:add(f.tag, t[1])
    end
    
    for i, value in ipairs(t) do
        if i ~= 1 then
            what_tree:add(f.param, value)
        end
    end
end

function parse_params(field)
    local t = {}
    t[1] = string.match(field, "^([0-9]*)")

    for str in string.gmatch(field, "#([0-9]*)") do
        if str:len() > 0 then
            table.insert(t, tonumber(str))
        end
    end

    return t
end

function parse_message(msg)
    local t = {}
    local i = 0
    for str in string.gmatch(msg, "([*][0-9#]*)") do
        if str:len() > 0 then
            if i == 0 then
                local p = string.match(str, "[*]#?(%d*)")
                table.insert(t, tonumber(p))
            elseif str == "*" then
                table.insert(t, "")
            else
                local p = string.match(str, "[*](.*)")
                if string.match(p, "##$") then
                    p = string.match(p, "(.*)##$") 
                end
                table.insert(t, p)
            end
            i = i + 1
        end
    end
    
    return t
end

function m_open_session(string)
    local str = string:match("^[*]99[*]%d##")
    if str then
        return true
    else
        return false
    end
end

function m_rqt_hmac(string)
    local str = string:match("^[*]98[*]%d##")
    if str then
        return true
    else
        return false
    end
end

function m_nonce(string)
    local str = string:match("^[*]#%d+##")
    if str then
        return true
    else
        return false
    end
end

function m_ack(string)
    local str = string:match("^[*]#[*]1##")
    if str then
        return true
    else
        return false
    end
end

function m_nack(string)
    local str = string:match("^[*]#[*]0##")
    if str then
        return true
    else
        return false
    end
end

function m_norm(string)
    local str = string:match("^[*]%d+[*]%d*[#%d]*[*]%d+[#%d]*##")
    if str then
        return true
    else
        return false
    end
end

function m_sts(string)
    local str = string:match("^[*]#%d+[*]%d*[#%d]*##")
    if str then
        return true
    else
        return false
    end
end

function m_dim_req(string)
    local str = string:match("^[*]#%d+[*]%d*[#%d]*[*]%d+[#%d]*##")
    if str then
        return true
    else
        return false
    end
end

function m_dim_wtr(string)
    local str = string:match("^[*]#%d+[*]%d*[#%d]*[*]%d*[#%d]*[%d*]*##")
    if str then
        return true
    else
        return false
    end
end


tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(20000, own)
