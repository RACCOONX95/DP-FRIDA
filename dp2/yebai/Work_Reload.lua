local luv = require("luv")
local dp = _DP
local dpx = _DPX
local game = require("df.game")
local logger = require("df.logger")
local item_handler = { }

-- 以下是跨界石代码 只要在背包装备栏的第一格，无论什么品级都可以被转移（不用就删掉这一大段）!
item_handler[123001] = function(user, item_id)
    local list = {16814, 16814, 16814, 16814, 16814} -- 不可转移的装备代码
    local boolx = false
    local info = dpx.item.info(user.cptr, game.ItemSpace.INVENTORY, 9)
    if info then
        for _, _equip in pairs(list) do
            if info.id == _equip then
                boolx = true
                break
            end
        end
        if not boolx then
            if not user:MoveToAccCargo(game.ItemSpace.INVENTORY, 9) then
                user:SendNotiPacketMessage("转移失败，请检查装备栏第一格是否有装备或者账号仓库是否开启!", 1)
                dpx.item.add(user.cptr, item_id)
            else
                user:SendNotiPacketMessage("恭喜您，装备栏第一格物品已经转移到账号仓库!", 1)
            end
        end
        if boolx then
            dpx.item.add(user.cptr, item_id, 1)
            user:SendNotiPacketMessage("抱歉，该物品不可转移!", 1)
        end
    else
        dpx.item.add(user.cptr, item_id, 1)
        user:SendNotiPacketMessage("请确保装备栏第一格的装备正确", 1)
    end
end
-- 以上是跨界石代码 只要在背包装备栏的第一格，无论什么品级都可以被转移（不用就删掉这一大段）!

--这里是避免被任务完成券所完成的任务代码，如果有不想被完成的任务，可以填代码到这里，按格式来填！
evade_lst = { 
--与赛利亚初次见面
1016,
--辅助装备与魔法石
674, 649, 676, 675, 650, 677,
--快捷栏装备任务
9900,9901,9902,9903,9904,9905,9906,
--副职业
2708,2710,2712,2702,
--女鬼剑转职觉醒
8011,8012,8013,8014,
8016,8017,8018,8019,
--普通角色转职
7898,7889,7895,7892,7873,7876,7870,7879,
4065,4068,7827,7817,7824,7820,7834,7837,
7831,7840,7848,7842,7845,7851,7866,7855,
7862,7859,7814,7810,7807,7803,7886,7882,
--普通角色觉醒
7628,948,995,5329,5333,5340,5344,914,
925,988,967,919,5684,156,930,5321,
4086,7634,942,5314,5307,7618,936,
909,5678,981,903,5350,4082,974,
}
--这里是避免被任务完成券所完成的任务代码，如果有不想被完成的任务，可以填代码到这里，按格式来填！

-- 以下是主线任务完成券代码 自动完成符合等级的主线任务（不用就删掉这一大段）!
item_handler[123002] = function(user, item_id)
    local quest = dpx.quest
    local lst = quest.all(user.cptr)
    local chr_level = user:GetCharacLevel()
    local new_lst = {}
    
    for i, v in ipairs(lst) do
        local is_evade = false
        for j, w in ipairs(evade_lst) do
            if v == w then
                is_evade = true
                break
            end
        end
        if not is_evade then
            new_lst[#new_lst + 1] = v
        end
    end
    
    for i, v in ipairs(new_lst) do
        local id = v
        local info = quest.info(user.cptr, id)
        if info then
            if not info.is_cleared and info.type == game.QuestType.epic and info.min_level <= chr_level then
                quest.clear(user.cptr, id)
            end
        end
    end
    
    quest.update(user.cptr)
end
-- 以上是任务完成券代码 自动完成符合等级的主线任务（不用就删掉这一大段）!

-- 以下是普通任务完成券代码 自动完成符合等级的普通任务（不用就删掉这一大段）!
item_handler[123003] = function(user, item_id)
    local quest = dpx.quest
    local lst = quest.all(user.cptr)
    local chr_level = user:GetCharacLevel()
    local new_lst = {}
    
    for i, v in ipairs(lst) do
        local is_evade = false
        for j, w in ipairs(evade_lst) do
            if v == w then
                is_evade = true
                break
            end
        end
        if not is_evade then
            new_lst[#new_lst + 1] = v
        end
    end
    
    for i, v in ipairs(new_lst) do
        local id = v
        local info = quest.info(user.cptr, id)
        if info then
            if not info.is_cleared and info.type == game.QuestType.common_unique and info.min_level <= chr_level then
                quest.clear(user.cptr, id)
            end
        end
    end
    
    quest.update(user.cptr)
end
-- 以上是任务完成券代码 自动完成符合等级的普通任务（不用就删掉这一大段）!

-- 以下是成就任务完成券代码 自动完成符合等级的成就任务（不用就删掉这一大段）!
item_handler[123004] = function(user, item_id)
    local quest = dpx.quest
    local lst = quest.all(user.cptr)
    local chr_level = user:GetCharacLevel()
    local new_lst = {}
    
    for i, v in ipairs(lst) do
        local is_evade = false
        for j, w in ipairs(evade_lst) do
            if v == w then
                is_evade = true
                break
            end
        end
        if not is_evade then
            new_lst[#new_lst + 1] = v
        end
    end
    
    for i, v in ipairs(new_lst) do
        local id = v
        local info = quest.info(user.cptr, id)
        if info then
            if not info.is_cleared and info.type == game.QuestType.achievement and info.min_level <= chr_level then
                quest.clear(user.cptr, id)
            end
        end
    end
    
    quest.update(user.cptr)
end
-- 以上是成就任务完成券代码 自动完成符合等级的成就任务（不用就删掉这一大段）!

-- 以下是异界2 次数重置券（不用就删掉这一大段）!
item_handler[123005] = function(user, item_id)
    user:ResetDimensionInout(0)
    user:ResetDimensionInout(1)
    user:ResetDimensionInout(2)
end
-- 以下是异界3 次数重置券（不用就删掉这一大段）!
item_handler[123006] = function(user, item_id)
    user:ResetDimensionInout(3)
    user:ResetDimensionInout(4)
    user:ResetDimensionInout(5)
end

-- 以下是装备继承券 将装备背包中的第一格道具的强化/增幅继承到第二格道具上（不用就删掉这一大段）!
item_handler[123007] = function(user, item_id)
    local mask = game.InheritMask.FLAG_UPGRADE | game.InheritMask.FLAG_AMPLIFY | game.InheritMask.FLAG_ENCHANT | game.InheritMask.FLAG_SEPARATE
    mask = mask | game.InheritMask.FLAG_MOVE_UPGRADE | game.InheritMask.FLAG_MOVE_AMPLIFY | game.InheritMask.FLAG_MOVE_ENCHANT | game.InheritMask.FLAG_MOVE_SEPARATE

    local yebai1 = dpx.item.info(user, game.ItemSpace.INVENTORY, 9)
    local yebai2 = dpx.item.info(user, game.ItemSpace.INVENTORY, 10)

    if yebai1 == nil or yebai2 == nil then
        user:SendNotiPacketMessage("注意：装备栏1或装备栏2的装备数据无法被识别！", 1)
        dpx.item.add(user.cptr, item_id)
    else
        if math.abs(yebai2.usable_level - yebai1.usable_level) <= 10 then
            if yebai1.rarity == yebai2.rarity then
                if yebai1.usable_level >= 40 then
                    if yebai1.amplify.type == 0 and yebai2.amplify.type ~= 0 then
                        dpx.item.add(user.cptr, item_id)
                        user:SendNotiPacketMessage("注意：强化装备不可以继承给增幅装备！", 1) -- 给出反馈
                    elseif not dpx.item.inherit(user.cptr, 9, 10, mask) then
                        dpx.item.add(user.cptr, item_id)
                    else
                        user:SendNotiPacketMessage("恭喜：已经成功继承！", 1) -- 给出成功的反馈
                    end
                else
                    dpx.item.add(user.cptr, item_id)
                    user:SendNotiPacketMessage("注意：低于40级的装备不可以继承！", 1)  -- 给出反馈
                end
            else
                dpx.item.add(user.cptr, item_id)
                user:SendNotiPacketMessage("注意：品级相同才可以继承！", 1)  -- 给出反馈
            end
        else
            dpx.item.add(user.cptr, item_id)
            user:SendNotiPacketMessage("注意：等级差必须小于等于10级的装备才可以被继承！", 1)
        end
    end
end
-- 以上是装备继承券 将装备背包中的第一格道具的强化/增幅继承到第二格道具上（不用就删掉这一大段）!

-- 以下是20级直升券代码 升到20级并清理前19级任务，可在20级前任意一级使用（不用就删掉这一大段）!
item_handler[123008] = function(user, item_id)
    local currentLevel = user:GetCharacLevel()
    if currentLevel >= 20 then
        dpx.item.add(user.cptr, item_id)
        user:SendNotiPacketMessage("\n当前用户不满足低于20级条件，无法使用20级直升券！", 1)
    else
        for i = currentLevel, 18, 1 do
            user:AddCharacExpPercent(1)
        end
        logger.info(string.format("%d 升到19级", user:GetCharacNo()))
        local quest = dpx.quest
        local lst = quest.all(user.cptr)
        local chr_level = user:GetCharacLevel()
        --下面{}内写要排除的任务编号即可，就不会自动完成如下编号的任务。
        local evade_lst = {}
        for i, v in ipairs(lst) do
            for j, w in ipairs(evade_lst) do
                if v == w then
                    table.remove(lst, i)
                end
            end
        end
        for i, v in ipairs(lst) do
            local id = v
            local info = quest.info(user.cptr, id)
            if info then
                if not info.is_cleared and info.type == game.QuestType.epic and info.min_level <= chr_level then
                    quest.clear(user.cptr, id)
                end
            end
        end
        quest.update(user.cptr)
        logger.info(string.format("%d 19级主线清理完成", user:GetCharacNo()))
        user:AddCharacExpPercent(1)
        logger.info(string.format("%d 升到20级", user:GetCharacNo()))
    end
end
-- 以下是20级直升券代码 升到20级并清理前19级任务（不用就删掉这一大段）!

-- 以下是宠物删除券代码 删除宠物前5栏（不用就删掉这一大段）!
item_handler[123009] = function(user, item_id)
    for i = 0, 4, 1 do
        local info = dpx.item.info(user.cptr, game.ItemSpace.CREATURE, i)
        if info then
            logger.info(string.format("will delete [iteminfo] id: %d count: %d name: %s attach: %d",
                    info.id, info.count, info.name, info.attach_type))
            dpx.item.delete(user.cptr, game.ItemSpace.CREATURE, i)
        end
    end
    user:SendItemSpace(game.ItemSpace.CREATURE)
    user:SendNotiPacketMessage("\n已清理宠物前5栏！", 1)
end
-- 以下是宠物删除券代码 删除宠物前5栏（不用就删掉这一大段）!

-- 以下是懸賞令 - 巨灵布鲁 强制接取懸賞令 - 牛頭械王任务（不用就删掉这一大段）!
item_handler[123010] = function(user, item_id)
    dpx.quest.accept(user, 140, true)
    dpx.quest.update(user)
end
-- 以下是懸賞令 - 巨灵布鲁 强制接取懸賞令 - 牛頭械王任务（不用就删掉这一大段）!

-- 副职业一键分解券 需要学习分解师副职（不用就删掉这一大段）!
item_handler[123011] = function(user, item_id)
    dpx.item.add(user.cptr, item_id)
    for i = 9, 100, 1 do
        local info = dpx.item.info(user.cptr, game.ItemSpace.INVENTORY, i)
        if info then
            logger.info(string.format("will Disjoint [iteminfo] id: %d count: %d name: %s attach: %d",
                    info.id, info.count, info.name, info.attach_type))
            user:Disjoint(game.ItemSpace.INVENTORY, i, user)
        end
    end
    user:SendItemSpace(game.ItemSpace.INVENTORY)
    user:SendNotiPacketMessage("\n装备分解完成！", 1)
end
-- 副职业一键分解券 需要学习分解师副职（不用就删掉这一大段）!

--装备回收箱/回收装备栏第一行（不用就删掉这一大段）!
item_handler[123012] = function(user, item_id)
    local list1 = {27098, 27739, 27675} -- 可以回收的装备id
    local list2 = {3284, 3285} -- 回收奖励id
    local to_recycle = {} -- 待回收装备列表
    math.randomseed(tostring(os.time()):reverse():sub(1, 7))
    
    for i = 9, 16, 1 do
        local info = dpx.item.info(user.cptr, game.ItemSpace.INVENTORY, i)
        if info then
            for _, _equip in ipairs(list1) do
                if info.id == _equip then
                    table.insert(to_recycle, i)
                    
                    -- 在每回收一格物品后奖励一次
                    local n = math.random(1, #list2)
                    local count = math.random(10, 50)
                    dpx.item.add(user.cptr, list2[n], count)
                    dpx.item.delete(user.cptr, game.ItemSpace.INVENTORY, i, 1)

                    break
                end
            end
        end
    end

    if #to_recycle == 0 then
        dpx.item.add(user.cptr, item_id, 1)
        user:SendNotiPacketMessage("请确保装备栏前8格中的装备正确", 1)
    end
end
--装备回收箱/回收装备栏第一行（不用就删掉这一大段）!

-- 女鬼剑转换券（不用就删掉这一大段）!
item_handler[123013] = function(user, item_id)
    local charac_no = user:GetCharacNo()
    performCharacJobConversion(user, charac_no)
end
function performCharacJobConversion(user, charac_no)
    -- 清空 MySQL 模块缓存
    package.loaded["luasql.mysql"] = nil
    -- 定义 MySQL 模块通讯信息
    local mysql = require("luasql.mysql")
    local env = mysql.mysql()
    local yebaicain = assert(env:connect("taiwan_cain", "game", "uu5!^%jg", "127.0.0.1"))-- 这里的IP密码不需要进行更改
    -- 创建 MySQL 连接
    local env = assert(mysql.mysql())
    -- 查询角色信息
    local select_char_sql = string.format("SELECT * FROM charac_info WHERE charac_no = %d", charac_no)
    local select_stmt = assert(yebaicain:execute(select_char_sql))
    local row = select_stmt:fetch({}, "a")
    if row then
        -- 更新角色职业
        local covert_char_sql = string.format("UPDATE charac_info SET job = 10 WHERE charac_no = %d", charac_no)
        local update_stmt = assert(yebaicain:execute(covert_char_sql))
        user:SendNotiPacketMessage("\n恭喜您转职成功，请切换一下其他角色再切回来！", 1)
    else
        -- 角色不存在
        log("Character does not exist")
        dpx.item.add(user.cptr, item_id)
    end
end
-- 女鬼剑转换券（不用就删掉这一大段）!

-- 点券增加券（不用就删掉这一大段）!
item_handler[123014] = function(user, item_id)
    local cera_count = 1000
    user:ChargeCera(cera_count)
    local message = string.format("\n恭喜您获得%d点券！", cera_count)
    user:SendNotiPacketMessage(message, 1)
end
-- 点券增加券（不用就删掉这一大段）!

-- 宠物进化券（不用就删掉这一大段）!
item_handler[123015] = function(user, item_id)
    -- 宠物 ID 和进化后的宠物 ID
    local pet_id = 63116
    local evolved_pet_id = 100990058
    -- 宠物名称映射表
    local pet_name = {
        [pet_id] = "兔精灵卫队长月蝉",
        [evolved_pet_id] = "光咏之魂",
    }
    local pet_item1 = dpx.item.info(user.cptr, 7, 0)
    if not pet_item1 or pet_item1.id ~= pet_id then
        dpx.item.add(user.cptr, item_id)
        user:SendNotiPacketMessage("进化失败，请确保宠物栏第一格有[" .. pet_name[pet_id] .. "]宠物！", 1)
        return
    end
    dpx.item.delete(user.cptr, 7, 0, 1)
    dpx.item.add(user.cptr, evolved_pet_id, 1, 7, 0)
    user:SendNotiPacketMessage("恭喜，你的宠物[" .. pet_name[pet_id] .. "]成功进化为[" .. pet_name[evolved_pet_id] .. "]", 1)
end
-- 宠物进化券（不用就删掉这一大段）!

-- 以下是时装删除券代码 删除时装前5栏（不用就删掉这一大段）!
item_handler[123019] = function(user, item_id)
    for i = 0, 4, 1 do
        local info = dpx.item.info(user.cptr, game.ItemSpace.AVATAR, i)
        if info then
            logger.info(string.format("will delete [iteminfo] id: %d count: %d name: %s attach: %d",
                    info.id, info.count, info.name, info.attach_type))
            dpx.item.delete(user.cptr, game.ItemSpace.AVATAR, i)
        end
    end
    user:SendItemSpace(game.ItemSpace.AVATAR)
    user:SendNotiPacketMessage("\n已清理时装前5栏！", 1)
end
-- 以下是时装删除券代码 删除时装前5栏（不用就删掉这一大段）!

--修复绝望之塔金币异常
local function MyUseAncientDungeonItems(fnext, _party, _dungeon, _item)
    local dungeon = game.fac.dungeon(_dungeon)
    local dungeon_index = dungeon:GetIndex()
    if dungeon_index >= 11008 and dungeon_index <= 11107 then
        return true
    end
    return fnext()
end

--通用辅助函数，用于处理使用道具的逻辑，包括调用对应的处理函数和记录日志。
local my_useitem2 = function(_user, item_id)
    local user = game.fac.user(_user)
    local handler = item_handler[item_id]
    if handler then
        handler(user, item_id)
        logger.info("[useitem] acc: %d chr: %d item_id: %d", user:GetAccId(), user:GetCharacNo(), item_id)
    end
end

item_handler[123021] = function(user, item_id)
    user:ChangeGrowType(1, 0)
	user:SendNotiPacketMessage("\n恭喜您转职成功！", 1)
end
item_handler[123022] = function(user, item_id)
	user:SendNotiPacketMessage("\n恭喜您转职成功！", 1)
    user:ChangeGrowType(2, 0)
end
item_handler[123023] = function(user, item_id)
	user:SendNotiPacketMessage("\n恭喜您转职成功！", 1)
    user:ChangeGrowType(3, 0)
end
item_handler[123024] = function(user, item_id)
	user:SendNotiPacketMessage("\n恭喜您转职成功！", 1)
    user:ChangeGrowType(4, 0)
end
item_handler[123025] = function(user, item_id)
	user:SendNotiPacketMessage("\n恭喜您觉醒成功！", 1)
	user:ChangeGrowType(user:GetCharacGrowType(), 1)
end

--玩家在游戏内输入://签到	获得邮件奖励
--注意，如果重新跑五国后，签到时间将会重置
local lastSignInTime = {}  
local on_input = function(fnext, _user, input)
    local user = game.fac.user(_user)
    logger.info("INPUT|%d|%s|%s", user:GetAccId(), user:GetCharacName(), input)

    if input == "//签到" then
	
		if tonumber(os.date("%H", currentTime)) < 6 then
			local yesterday = os.time() - (24 * 60 * 60) -- 减去一天的秒数
			current_date = os.date("%Y-%m-%d", yesterday)
		else
			current_date = os.date("%Y-%m-%d")
		end
		local log_file_path = string.format("/dp2/yebai/sign_in_%s.log", current_date)
		local characName = user:GetCharacName()

		-- 尝试打开日志文件以读取内容
		local logFile = io.open(log_file_path, "r")

		if logFile then
			for line in logFile:lines() do
				if string.match(line, characName) then
					local currentTime = os.time()
					local lastMidnight = os.time({year=os.date("*t", currentTime).year, month=os.date("*t", currentTime).month, day=os.date("*t", currentTime).day, hour=0, min=0, sec=0})
					local nextSixAM = lastMidnight + 24 * 3600 + 6 * 3600  -- 下一天的早上6点
					local cooldown = nextSixAM - currentTime  -- 到下一天早上6点的剩余时间
					local remainingTime = cooldown

					if tonumber(os.date("%H", currentTime)) < 6 then
						remainingTime = remainingTime - (3600 * 24)
					end

					local hours = math.floor(remainingTime / 3600)
					local minutes = math.floor((remainingTime % 3600) / 60)
					local seconds = remainingTime % 60

					user:SendNotiPacketMessage("------------------------------------------", 1)
					user:SendNotiPacketMessage("您今天已经签到完毕，请勿重复签到！", 3)
					user:SendNotiPacketMessage(string.format("距离下次签到剩余时间：%d小时%d分钟%d秒", hours, minutes, seconds), 2)
					user:SendNotiPacketMessage("------------------------------------------", 1)
					return 0
				end
			end
			logFile:close() -- 关闭文件
		end
	
	
        dpx.mail.item(user:GetCharacNo(), 3, "每日低保", "感谢您的支持", "3037", "1")--3037为道具，1为数量
        dpx.mail.item(user:GetCharacNo(), 3, "每日低保", "感谢您的支持", "3037", "2")--3037为道具，2为数量
        dpx.mail.item(user:GetCharacNo(), 3, "每日低保", "感谢您的支持", "3037", "3")--3037为道具，3为数量
        user:SendNotiPacketMessage("------------------------------------------", 1)
        user:SendNotiPacketMessage("签到奖励发送完毕，如空邮件则小退一下!", 2)
        user:SendNotiPacketMessage("------------------------------------------", 1)

        lastSignInTime[user:GetCharacNo()] = currentTime

		local logFile = io.open(log_file_path, "a")
		if logFile then
			local logMsg = string.format("%s | %d | %s | %s\n", os.date("%Y-%m-%d %H:%M:%S"), user:GetAccId(), user:GetCharacName(), "玩家签到成功!")
			logFile:write(logMsg)
			logFile:close()
		end


        return 0
    end

    return fnext()
end

------------- 以下代码使用上方子程序功能的启动代码[前面加了--是代表不生效的意思，如需要某项功能，删除前面的--即可]--------------------- !
dpx.open_timegate()
--dpx.disable_redeem_item()-- 禁用支援兵
--dpx.disable_redeem_item()-- 关闭NPC回购系统 !
--dpx.set_max_level(100)-- 设置服务端等级上限 !
--dpx.disable_item_routing()-- 史诗免确认提示框 !
--dpx.set_item_unlock_time(1)-- 设置装备解锁时间
dpx.disable_giveup_panalty()-- 退出副本后角色默认不虚弱 !
dpx.set_auction_min_level(10)-- 设置使用拍卖行的最低等级
dpx.disable_mobile_rewards()-- 新创建角色没有成长契约邮件 !
dpx.disable_security_protection()-- 解除100级以及以上的限制 !
dpx.disable_trade_limit()-- 解除交易限额(已经达到上限的第二天生效) !
dpx.enable_creator()-- 开启创建缔造者接口，需要本地exe配合，建议0725 !
dpx.set_unlimit_towerofdespair()-- 绝望之塔通关后仍可继续挑战(需门票) !
dpx.extend_teleport_item()---扩展移动瞬间药剂ID: 2600014/2680784/2749064
dp.mem.hotfix(dpx.reloc(0x0808A9D9 + 1), 1, 0xB6)-- 修复小明公开的台服漏洞
dpx.fix_auction_regist_item(200000000)-- 修复拍卖行消耗品上架最大总价, 建议值2E !
dpx.hook(game.HookType.CParty_UseAncientDungeonItems, MyUseAncientDungeonItems)-- 修复绝望之塔金币提示异常 !
dpx.hook(game.HookType.UseItem2, my_useitem2)-- 跨界石、任务完成券、异界重置券、装备继承券、悬赏令任务hook !
dpx.hook(game.HookType.GmInput, on_input)--对于游戏内输入指令反馈和结果

