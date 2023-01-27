-- cmd aren't actually openwebnet commands, but are used to identify the type of message
local cmd = {
    [1] = "OPEN_SESSION",
    [2] = "NONCE",
    [3] = "PASSWORD",
    [4] = "ACK",
    [5] = "NACK",
    [6] = "NORMAL",
    [7] = "STATUS_REQUEST",
    [8] = "DIMENSION_REQUEST",
    [9] = "DIMENSION_WRITING"
}

local session = {
    [0] = "COMMAND_SESSION",
    [1] = "EVENT_SESSION"
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
    [13] = "Gateway Management",
    [14] = "Lighting",
    [15] = "CEN commands",
    [17] = "MH200N scenarios",
    [18] = "Energy management",
    [22] = "Sound diffusion",
    [24] = "Lighting management",
    [25] = "CEN plus / scenarios plus / dry contacts",
    [1001] = "Automation diagnostic",
    [1004] = "Thermoregulation diagnostic",
    [1013] = "Device diagnostic",
}


local own = Proto("own", "OpenWebNet protocol")

local f = own.fields
f.msg = ProtoField.string("own.msg", "Message")
f.cmd = ProtoField.uint8("own.cmd", "Command", base.HEX, cmd)
f.session = ProtoField.uint8("own.session", "Session Type", base.DEC, session)
f.who = ProtoField.uint16("own.who", "Who", base.DEC, who)
f.what = ProtoField.string("own.what", "What")
f.where = ProtoField.string("own.where", "Where")
f.dimension = ProtoField.string("own.dimension", "Dimension")
f.values = ProtoField.string("own.value", "Values")
f.value = ProtoField.string("own.value", "Value")
f.nonce = ProtoField.uint16("own.nonce", "Nonce")
f.password = ProtoField.uint16("own.password", "Password")

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
    if m_open_cmd(msg) then
        pkt_info.cols.info = cmd[1]
        main_tree:add(f.cmd, 1)
        main_tree:add(f.session, 0)
    elseif m_open_event(msg) then
        pkt_info.cols.info = cmd[1]
        main_tree:add(f.cmd, 1)
        main_tree:add(f.session, 1)
    elseif m_nonce(msg) then
        local nonce = string.match(msg, "%d+")

        if pkt_info.src_port == 20000 then
            pkt_info.cols.info = cmd[2]
            main_tree:add(f.cmd, 2)
            main_tree:add(f.nonce, tonumber(nonce))
        else
            pkt_info.cols.info = cmd[3]
            main_tree:add(f.cmd, 3)
            main_tree:add(f.password, tonumber(nonce))
        end        
    elseif m_ack(msg) then
        pkt_info.cols.info = cmd[4]
        main_tree:add(f.cmd, 4)
    elseif m_nack(msg) then
        pkt_info.cols.info = cmd[5]
        main_tree:add(f.cmd, 5)
    elseif m_norm(msg) then
        pkt_info.cols.info = cmd[6]
        main_tree:add(f.cmd, 6)

        local t = parse_message(msg)
        main_tree:add(f.who, t[1])
        main_tree:add(f.what, t[2])
        main_tree:add(f.where, t[3])
    elseif m_sts(msg) then
        pkt_info.cols.info = cmd[7]
        main_tree:add(f.cmd, 7)

        local t = parse_message(msg)
        main_tree:add(f.who, t[1])
        main_tree:add(f.where, t[2])
    elseif m_dim_req(msg) then
        pkt_info.cols.info = cmd[8]
        main_tree:add(f.cmd, 8)
        local t = parse_message(msg)

        main_tree:add(f.who, t[1])
        main_tree:add(f.where, t[2])
        main_tree:add(f.dimension, t[3])
    elseif m_dim_wtr(msg) then
        pkt_info.cols.info = cmd[9]
        main_tree:add(f.cmd, 9)
        local t = parse_message(msg)

        main_tree:add(f.who, t[1])
        main_tree:add(f.where, t[2])
        main_tree:add(f.dimension, t[3])
        values = main_tree:add(f.values, "")
        for i = 4, #t do
            values:add(f.value, t[i])
        end
    else
        return
    end
end

function split(inputstr, sep)
    if sep == nil then
            sep = "%s"
    end

    local t = {}
    for str in string.gmatch(inputstr, "([^"..sep.."]+)") do
        table.insert(t, str)
    end

    return t
end

function parse_string(str, pattern)
    str = str:sub(1, -2)
    str = str:sub(1, -2)

    local t = {}
    for str in string.gmatch(str, pattern) do
        table.insert(t, str)
    end
    return t
end

function parse_message(msg)
    local t = {}
    local i = 0
    for str in string.gmatch(msg, "([*][a-zA-Z0-9#]*)") do
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

function m_open_cmd(string)
    local str = string:match("^[*]99[*]0##")
    if str then
        return true
    else
        return false
    end
end

function m_open_event(string)
    local str = string:match("^[*]99[*]1##")
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
