------------------------------------------{ Salavat }------------------------------------------
--| Модуль информационной безопасности [версия: 1.0] |-----------------------------------------
-----------------------------------------------------------------------------------------------
--| Скорректированно: 2019.08.21 |-------------------------------------------------------------
-----------------------------------------------------------------------------------------------


--[[-------------------------------------------------------------------------------------------
	Для передачи файлов в Syslog
--]]-------------------------------------------------------------------------------------------
dofile('decode_Ansi_Utf8.lua');								-- Запускаем конвертер текста
computerName 	= os.getenv("computername");				-- Получаем имя компьютера
userName 		= os.getenv("username");					-- Получаем имя имя компьютера

--
-- Функции сохраняют на диск список событий + заполняют глобальные сигналы для их передачи на БД.
--

local function getEvent(arg)
	local sigSignals 	= arg[1];	-- [1] - перечень сигнальных сигналов;
	local prefix 		= arg[2];	-- [2] - префикс имени файла;
	local depth 		= arg[3];	-- [3] - глубина запроса данных [s];
	local interval 		= arg[4];	-- [4] - интервал запроса данных [s];
    local IBE_tab 		= arg[5];	-- [5] - структура с глобальными переменными;
	local ServerFlag 	= arg[6];	-- [6] - (не использую, беру на прямую).

-- Открываем файлы необходимые для работы
	dofile('InfSec/ConfigurationTab.lua')			-- таблица с характеристками проекта
	dofile('InfSec/TableEventID.lua');				-- открываем таблицу с идентификаторами для ИБ

-- Сбрасываем активные сигнальные сигналы.
	local dt_name = os.time();
	os.sleep(0);
	for _, name in ipairs(sigSignals) do
		if 	Core[name]==true then
			Core[name]=false;
		end
	end
-- Получаем текущее время.
	local dt = os.time();


-- Формируем имя файла.
	local fileName = prefix.."_Client"..os.date("_%Y%m%d_%H%M%S.log", dt_name);

-- Открываем файл.
	local file = io.open('log/'..fileName, "w+");
	if file == nil then os.execute("mkdir log") end	-- сделать проверку пути

	Core.addLogMsg("Оpen file Event");
	if file==nil then return end
	
-- Запрашиваем список событий от текущего времени и depth секунд назад.
	local events = Core.getEvents(dt-depth, dt);

	
	-- Начинаем сканировать
     for i=1,#events  do 

        local date = os.date("%Y.%m.%d ",		events[i].dt);
		local time = os.date("%H:%M:%S.%3N",	events[i].dt); 
		local getTextMes		= ''	-- Шаблон сообщения
 		local getEventID		= ''	-- ID события для ИБ
 		local getCodeSonata		= ''	-- Код события из Сонаты
 		local getSeverity		= ''	-- Серьезность сообщения]]
		-- записывем для передачи в лог
        Core[IBE_tab[1]] = date..time; 

        -- Получаем Узел и Приложение откуда прилетело сообщение
        if events[i].application ~= nil and events[i].application ~= '' then
        	getNode 		= '';
        	getApplication	= '';
        	aplicationTable = {}
 			local index = 1
 				for value in string.gmatch(events[i].application, "[^.]+") do 
					aplicationTable[index] = value
    				index = index + 1						
 				end
 			getNode 		= aplicationTable[1]; 	-- записываем имя Узла 			
 			getApplication	= aplicationTable[2];	-- записываем имя Приложения
 			else 	getNode 		= 'nil'
 					getApplication	= 'nil'
 		end

		--[[-- Выполняем сканирование TableEvent ----------------------------
 				Запоминаем переменные полученные из таблицы
 		--------------------------------------------------------------------]]
 		-- Перебираем таблицу
 		for u=1, #TableEvent do
			if events[i].msg ~= nil then
				if string.find(events[i].msg, TableEvent[u].TextMes) then
					getTextMes		= TableEvent[u].TextMes;		Core['tString[15]'] = TableEvent[u].TextMes;
					getEventID		= TableEvent[u].EventID;		Core['tString[16]'] = TableEvent[u].EventID;
					getCodeSonata	= TableEvent[u].CodeSonata;		Core['tString[17]'] = TableEvent[u].CodeSonata;
					getSeverity		= TableEvent[u].Severity;		Core['tString[18]'] = TableEvent[u].Severity;
					break
				else	getTextMes		= 'noTgetTextMes';
						getEventID		= '0';
						getCodeSonata	= 'noTgetCodeSonata';
						getSeverity		= 'noTgetSeverity';
				end
			end	
		end

		--[[-- Заполнение таблицы Meta -----------------------------------
 				Сканирование переменной meta и занесение значений в таблицу
 		--------------------------------------------------------------------]]
--[[ 		 		metaTable = {}
 					local index = 1
 					for value in string.gmatch(events[i].meta, "%w+") do 
						metaTable[index] = value
    					index = index + 1						
 					end]]
 		local metaTable = {}													-- таблица для заполнения данных из Meta
 		if events[i].meta ~= nil then 						
 				for k, v in string.gmatch(events[i].meta, "(%w+)=(%w+)") do
   					metaTable[k] = v
 				end
 		end
		--[[-- Заполнение Severity -----------------------------------------
 				Получение серьезности события
 					[1=Низкая 2=Высокая]
 		--------------------------------------------------------------------]]
        local t = {['1']='Низкая', ['2']='Высокая'};
	    if metaTable.Severity ~= nil then
			Core[IBE_tab[3]]	= string.gsub(tostring(metaTable.Severity), "(%d+)", t);	-- получаем Критичность
		else 
			Core[IBE_tab[3]] 	= string.gsub(tostring(getSeverity), "(%d+)", t);
		end



		-- Тестовые переменные - НАЧАЛО
				Core['tString[1]'] = tostring(events[i].pos);
				Core['tString[2]'] = tostring(events[i].dt);
				Core['tString[3]'] = tostring(events[i].userDT);			-- nil
				Core['tString[4]'] = tostring(events[i].application); 		-- test_PLC.AServ
				Core['tString[5]'] = tostring(events[i].source); 			-- ГПА2  АС - Вытаскиваем АС, и тд
				Core['tString[6]'] = tostring(events[i].user); 				-- 1
				Core['tString[7]'] = tostring(events[i].meta);				-- NOb.CGPA2_.AS..Ptg_in_TRK_Av
				Core['tString[8]'] = tostring(events[i].state);
				Core['tString[9]'] = tostring(events[i].msg);
				Core['tString[10]'] = tostring(events[i].catergory); 		-- Пишет nil
		-- Тестовые переменные - КОНЕЦ


		local meta = 'meta'; 		-- IF на следующей строке не позвояет плучить корректное значение поля meta, 
									-- появляется ошибка о том, что meta = nil, даже с цчетом ветки else 

		if  string.format("%s", events[i].meta)~= nil then 
							local meta = string.format("%s", events[i].meta);

						else 
							local meta = 'meta';
						end

        if string.find(meta, 'AOs') ~=nil or string.find(meta, 'AOb')~=nil or string.find(meta, 'eventIB') ~=nil then
          Core[IBE_tab[2]] = Core[IBE_tab[2]] + 1;  
		else 
			Core[IBE_tab[2]] = 22;
		end

		--[[-- Заполнение таблицы EventName -----------------------------------
 			 	Имя произошедшего события
 		--------------------------------------------------------------------]]
        local date_ch = string.format("%s", events[i].dt);						-- системное время возникновения 
        local msg = string.gsub(events[i].msg, date_ch, "");	
		Core[IBE_tab[5]] = msg;

		--[[-- Заполнение таблицы EventID -----------------------------------
 				Для получения EventID сравниваем каждое сообщение с шаблоном
 		--------------------------------------------------------------------]]
		if getEventID ~= nil then
					Core[IBE_tab[4]]	= tostring(getEventID)
			else 	Core[IBE_tab[4]]	= 'EventID';
		end

		--[[-- Заполнение таблицы UserName-----------------------------------
 				Получаем текущее имя пользователя
 		--------------------------------------------------------------------]]
		local user = string.format("%s", events[i].user);						-- имя пользователя, вызвавшего данное событие
		if  user ~= nil and user ~= '' then 
			Core[IBE_tab[6]] = user;
		else
			Core[IBE_tab[6]] = ''												-- есть момент когда Пользователь еще не залогинился
		end											 

		--Core[IBE_tab[5]] = Utf8ToAnsi("Сообщение о событии"); 
		--Core[IBE_tab[5]] = AnsiToUTF8(Core[IBE_tab[5]]);

		--Core[IBE_tab[5]] = AnsiToUtf("Сообщение о событии");
		--local msg_test = '';
		--utf8_insert(msg_test,"Сообщение о событии",0);


--[[    local source 		= string.format("%s", events[i].source);					-- источник события
		local sourceName 	= string.sub(source, 5);
        local application 	= string.format("%s", events[i].application); 				-- имя приложения, породившее событие]]


		--[[-- Заполнение таблицы Client -----------------------------------
 				Записываем IP адрес АРМ и его сетевое имя
 		--------------------------------------------------------------------]]
		for c = 1, #Client do
			if getNode == Client[c].NodeName and getNode ~=nil then 
				--[[ ! у нас от одного до 4-х IP адресов нужно подумать как выдавать активный]]
				Core[IBE_tab[7]]	= Client[c].NodeIP;
				Core[IBE_tab[8]]	= Client[c].ARMname;
				break
			else 
				Core[IBE_tab[7]]	= 'nil';
				Core[IBE_tab[8]]	= 'nil';
			end
		end

		--[[-- Заполнение таблицы по Server -----------------------------------
 				Записываем IP и Имя 'основгого сервера' - MainServerFlag
 		--------------------------------------------------------------------]]
			if Core.MainServerFlag == 1 then
				Core[IBE_tab[9]]	= Server[Core.MainServerFlag].IPAddress;
				Core[IBE_tab[10]]	= Server[Core.MainServerFlag].HostName;
			elseif Core.MainServerFlag == 2 then
				Core[IBE_tab[9]]	= Server[Core.MainServerFlag].IPAddress;
				Core[IBE_tab[10]]	= Server[Core.MainServerFlag].HostName;
			else
				Core[IBE_tab[9]]	= 'nil';
				Core[IBE_tab[10]]	= 'nil';
			end

		--[[-- Заполнение таблицы по Target -----------------------------------
 				Присвоение адреса целевого узла (ГПА) согласно префиксу Source
 		--------------------------------------------------------------------]]
 		-- Обрабатываем Source
 		if events[i].source ~= nil and events[i].source ~= '' then  
			local sourceTab	= {}
			local indexS 	= 1
			local getNameSource = ''
			local getTypeSource	= ''
				for value in string.gmatch(events[i].source, "[^%s]+") do 
					sourceTab[indexS] = value
    				indexS = indexS + 1						
 				end
			getNameSource 		= sourceTab[1]; 	-- записываем имя Узла 			
 			getTypeSource		= sourceTab[2];		-- записываем имя Приложения 			
 		else 	getNameSource 	= 'Система'		-- Префикс источника
 				getTypeSource	= 'Система'		-- Тип источника
 		end

		for t=1, #Target do
			if getNameSource ~= nil then
				if getNameSource == Target[t].NameRU then
        				Core[IBE_tab[11]] = Target[t].Name;
        				Core[IBE_tab[12]] = Target[t].IPAddress;
						Core[IBE_tab[13]] = Target[t].HostName;
						break
					else
						Core[IBE_tab[11]] = "nil";
						Core[IBE_tab[12]] = "nil";
						Core[IBE_tab[13]] = "nil";
				end	
			end
		end
	
		--[[ -- Заполнение таблицы по Result
 					Результат произошедшего события (успешный или не успешный)
					[Success=Успех, Failed=Неудача]
 		--------------------------------------------------------------------]]
--[[ 		local getResult	= ''
	    if metaTable.Result ~= nil then
			getResult	= tostring(metaTable.Result);
		else 		
			getResult	= "Success";
		end]]

		Core[IBE_tab[14]]	= "Success";

		--[[-- Заполнение таблицы по Detail -----------------------------------
				Поле не обязательное
				На текущий момент расшифровывается статус сообщения
 		--------------------------------------------------------------------]]
        local state = string.format("%s", events[i].state); 
        if 		state == '769'	then state = "Появление"
        elseif 	state == '1' 	then state = "Появление"
        elseif 	state == '2' 	then state = "Квитирована"
        elseif 	state == '3' 	then state = "Исчезла"
        elseif 	state == '0' 	then state = "Пропадание"
        else state = "Пропадание" end  -- 769? 
		Core[IBE_tab[15]] = state;
        

-- Заполнение файла Syslog. =================================================================================================================================================
		-- Перечень регистрируемых параметров событий клиентского приложения 
			-- Обязательные поля (обязательные)
		local timeText 				= os.date("%b  %d  %H:%M:%S  ", dt);	-- Время регистрации события
		local eventCategory 		= "EventCategory"; 						-- Категория события	(? из events[i].category ?)
		local severityText 			= Core[IBE_tab[3]];						-- Серьезность (критичность) события [0-3=Low 4-6=Medium 7-8=High 9-10=Very-High]
		local idText 				= Core[IBE_tab[4]];			-- Код (идентификатор) произошедшего события
		local labelEvent 			= "SCADA-"..eventCategory.."-"..idText;	-- Заголовок
		local eventNameText 		= Core[IBE_tab[5]];			-- Наименование произошедшего события
		local userNameText 			= Core[IBE_tab[6]];						-- Идентификатор пользователя-инициатора события в виде уникального имени
		local clientAddressText 	= Core[IBE_tab[7]];						-- Сетевой адрес Ipv4 АРМ клиента (пользователя), инициировавшего событие
		local clientHostNameText 	= Core[IBE_tab[8]];						-- Сетевое имя АРМ клиента (пользователя), инициировавшего событие
		local serverAddressText 	= Core[IBE_tab[9]];						-- Сетевой адрес Ipv4 сервера SCADA
		local serverNameText 		= Core[IBE_tab[10]];					-- Сетевое имя сервера SCADA
		local targetUserNameText 	= Core[IBE_tab[11]];		-- Идентификатор пользователя или группы, на которых нацелено событие в виде уникального имени
		local targetAddressText 	= Core[IBE_tab[12]];		-- Сетевой адрес Ipv4 АРМ, на который нацелено событие
		local targetHostNameText 	= Core[IBE_tab[13]];		-- Сетевое имя АРМ, на которое нацелено событие
		local resultText 			= Core[IBE_tab[14]];					-- Результат произошедшего события (успешный или не успешный)
			-- Дополнительные поля (необязательные)
		local detailText 			= Core[IBE_tab[15]];					-- Дополнительная информация по произошедшему событию (любые данные)
		-- так же возможно добавить поле при нобходимости
--============================================================================================================================================================================

		file:write( "- "..os.date("%b  %d  %H:%M:%S.%3N ",	events[i].dt)..clientHostNameText.."\t"..labelEvent..": \n"..
					"Severity="..severityText..";EventID="..idText..";EventName="..eventNameText..
					";UserName="..userNameText..";ClientAddress="..clientAddressText..
					";ServerAddress="..serverAddressText..";ServerHostName=".. serverNameText..
					";TargetUserName="..targetUserNameText..";TargetAddress="..targetAddressText..
					";TargetHostName="..targetHostNameText..";Result="..resultText..";Detail="..detailText.."\n");
         Core[IBE_tab[16]] = true;     

         while  Core[IBE_tab[16]] == true do
         	--do
         end
	end
 
	file:close();
	file = nil;
	Core.addLogMsg("Close file Event");
end



local function getTehEvent(arg)
	local sigSignals = arg[1];  -- [1] - перечень сигнальных сигналов;
	local prefix = arg[2];      -- [2] - префикс имени файла;
	local depth = arg[3];       -- [3] - глубина запроса данных [s];
	local interval = arg[4];    -- [4] - интервал запроса данных [s];
    local IBE_tab = arg[5];
	local ServerFlag = arg[6];

	dofile('ClientTab.lua');
	dofile('ServerTab.lua');
	dofile('makePar/TableEventID.lua');		-- открываем таблицу с идентификаторами для ИБ

-- Сбрасываем активные сигнальные сигналы.
	local dt_name = os.time();
	os.sleep(0);
	for _, name in ipairs(sigSignals) do
		if Core[name]==true then
			Core[name]=false;
		end
	end
-- Получаем текущее время.
	local dt = os.time();
	
-- Формируем имя файла.
	local fileName = prefix.."_Teh"..os.date("_%Y%m%d_%H%M%S.log", dt_name);

-- Открываем файл.
	local file = io.open('log/'..fileName, "w+");
	Core.addLogMsg("Оpen file Event");
	if file==nil then return end
	
-- Запрашиваем список событий от текущего времени и depth секунд назад.
	local events = Core.getEvents(dt-depth, dt);


     for i=1,#events  do
        local date = os.date("%Y.%m.%d ", events[i].dt);
		local time = os.date("%H:%M:%S.%3N", events[i].dt); 
        Core[IBE_tab[1]] = date..time; 



        if events[i].groupUUID ~= nil then 
			Core[IBE_tab[3]] = string.format("%s",events[i].groupUUID); 
		else 
			Core[IBE_tab[3]] = "Severity";
		end




		local meta = 'meta'; 		-- IF на следующей строке не позвояет плучить корректное значение поля meta, 
									-- появляется ошибка о том, что meta = nil, даже с цчетом ветки else 

		if  string.format("%s", events[i].meta)~= nil then 
			local meta = string.format("%s", events[i].meta); 
		else 
			local meta = 'meta';
		end

		-- Для получения EventID прогоняю шаблоны сообщений
		for i=1, #TableEvent do
		if string.find(Utf8ToAnsi(msg), Utf8ToAnsi(TableEvent[i].TextMes)) ~= nil and string.find(Utf8ToAnsi(msg), Utf8ToAnsi(TableEvent[i].TextMes)) > 0 then
					Core[IBE_tab[4]] = TableEvent[i].EventID
					else
					Core[IBE_tab[4]] =  'EventID';
				end	
		end
       	--Core[IBE_tab[4]] = 4; --EventID - требуется число




        if string.find(meta, 'AOs') ~=nil or string.find(meta, 'AOb')~=nil or string.find(meta, 'eventIB') ~=nil then
          Core[IBE_tab[2]] = Core[IBE_tab[2]] + 1;  
		else 
			Core[IBE_tab[2]] = 2;
		end



		
        local date_ch = string.format("%s", events[i].dt);				--системное время возникновения 
        local msg = string.gsub(events[i].msg, date_ch, "");			--замена системного времени возникновения на ""
		Core[IBE_tab[5]] = Utf8ToAnsi(msg); 

		--Core[IBE_tab[5]] = Utf8ToAnsi("Сообщение о событии"); 
		--Core[IBE_tab[5]] = AnsiToUTF8(Core[IBE_tab[5]]);

		--Core[IBE_tab[5]] = AnsiToUtf("Сообщение о событии");
		--local msg_test = '';
		--utf8_insert(msg_test,"Сообщение о событии",0);


--Присвоение адреса сервера согласно флагу "основного сервера" MainServerFlag
 		if ServerFlag == 1 then
				Core[IBE_tab[6]] = Server[ServerFlag].IPAddress;
				Core[IBE_tab[7]] = Server[ServerFlag].HostName;
			elseif ServerFlag == 2 then
				Core[IBE_tab[6]] = Server[ServerFlag].IPAddress;
				Core[IBE_tab[7]] = Server[ServerFlag].HostName;
			else
				Core[IBE_tab[6]] = '6.6.6.6';
				Core[IBE_tab[7]] = "ServerHostName";
		end



        local source = string.format("%s", events[i].source);			-- источник события

		if source ~= '' then 
        		Core[IBE_tab[8]] = source;
		else 
				Core[IBE_tab[8]] = "source";
		end

		local info; -- используется в качестве шаблона для дальнейшей замены на источник информации о сигнале 

		if info ~=nil then 
        		Core[IBE_tab[9]] = info;
		else 
				Core[IBE_tab[9]] = 9;
		end

		if info ~=nil then 
        		Core[IBE_tab[10]] = info;
		else 
				Core[IBE_tab[10]] = "SignalStringValue";
		end

		if info ~=nil then 
        		Core[IBE_tab[11]] = info;
		else 
				Core[IBE_tab[11]] = "SignalValueDimension";
		end

		if info ~=nil then 
        		Core[IBE_tab[12]] = info;
		else 
				Core[IBE_tab[12]] = "SignalValueUnit";
		end

		if info ~=nil then 
        		Core[IBE_tab[13]] = info;
		else 
				Core[IBE_tab[13]] = "SignalType";
		end


		if info ~=nil then 
        		Core[IBE_tab[14]] = info;
		else 
				Core[IBE_tab[14]] = "AlarmState";
		end


        local application = string.format("%s", events[i].application); -- имя приложения, породившее событие

		for i = 1, #Client do   -- скорее всего для Оператора нужна другая таблица или не нужна вообще 
        	if application == Client[i].Name and application ~=nil then 
        		Core[IBE_tab[15]] = Client[i].Name;
				Core[IBE_tab[16]] = Client[i].Name;
			else 
				Core[IBE_tab[15]] = 'OperatorNode';
				Core[IBE_tab[16]] = 'OperatorName';
			end
		end

		if info ~=nil then 
        		Core[IBE_tab[17]] = info;
		else 
				Core[IBE_tab[17]] = "ThresholdValue";
		end

		if info ~=nil then 
        		Core[IBE_tab[18]] = info;
		else 
				Core[IBE_tab[18]] = 18;
		end

		Core[IBE_tab[19]] = "Result";

        local state = string.format("%s", events[i].state); 
        if state == '769' then state = "Появление" else state = "Пропадание" end  -- 769? 

		
		Core[IBE_tab[20]] = Utf8ToAnsi(state);
        
--заполнение файла Syslog
		
		local timeText = os.date("%b  %d  %H:%M:%S  ", dt);
		local eventCategory = "EventCategory"; 			-- ? из events[i].category ?
		local severityText = Core[IBE_tab[3]];
		local idText = Core[IBE_tab[4]];
		local labelEvent = "SCADA-"..eventCategory.."-"..idText;
		local eventNameText = Core[IBE_tab[5]];	
		local serverAddressText = Core[IBE_tab[6]];
		local serverNameText = Core[IBE_tab[7]];
		local signalSourceText = Utf8ToAnsi(Core[IBE_tab[8]]);
		local signalValueText = Core[IBE_tab[9]];
		local signalStrinagValueText = Core[IBE_tab[10]];
		local signalValueDimensionText = Core[IBE_tab[11]];
		local signalValueUnitText = Core[IBE_tab[12]];
		local signalTypeText = Core[IBE_tab[13]];
		local alarmStateText = Core[IBE_tab[14]];
		local operatorNodeText = Core[IBE_tab[15]];
		local operatorNameText = Core[IBE_tab[16]];
		local thresholdValueText = Core[IBE_tab[17]];
		local signalDeviationText = Core[IBE_tab[18]];
		local resultText = Core[IBE_tab[19]];
		local detailText = Core[IBE_tab[20]];

		file:write( "- "..timeText..serverNameText.."\t"..labelEvent..": \n"..
					"Severity="..severityText..";EventID="..idText..";EventName="..eventNameText..
					";ServerAddress="..serverAddressText..";SignalSource="..signalSourceText..";SignalValue="..signalValueText..
					";SignalStrinagValue="..signalStrinagValueText..";SignalValueDimension="..signalValueDimensionText..
					";SignalValueUnit="..signalValueUnitText..";SignalType="..signalTypeText..";AlarmState="..alarmStateText..
					";OperatorNode="..operatorNodeText..";OperatorName="..operatorNameText..";ThresholdValue="..thresholdValueText..
					";SignalDeviation="..signalDeviationText..";Result="..resultText..";Detail="..detailText.."\n");

       	Core[IBE_tab[21]] = true;       
        
	end
 
	file:close();
	file = nil;
	Core.addLogMsg("Close file Event");

end

Core.onTimer(3, 
             30,
				getEvent,							-- Вызываемая функция
				{
					{},								-- Передаём в обработчик перечень имён сигналов, при изменении которых выполнился вызов функции, чтобы сбросить их.
					"Syslog",					    -- Префикс имени файла.
					30, 							-- Глубина запроса данных [s].
					0.1,							-- Интервал запроса данных [s];
                    {	"IBE.Timestamp",			--1
						"IBE.EventNumber",			--2
						"IBE.Severity",				--3
						"IBE.EventID",				--4
						"IBE.EventName",			--5
						"IBE.UserName",				--6
						"IBE.ClientAddress",		--7
						"IBE.ClientHostName",		--8
						"IBE.ServerAddress",		--9
						"IBE.ServerHostName",		--10
						"IBE.TargetUserName",		--11
						"IBE.TargetAddress",		--12
						"IBE.TargetHostName",		--13
						"IBE.Result",				--14
						"IBE.Detail",				--15
						"IBE.StartWrihtSQL"},		--16
					Core.MainServerFlag
				},             
				 true )

--[[Core.onTimer(4, 
             10,
				getTehEvent,							-- Вызываемая функция
				{
					{},								-- Передаём в обработчик перечень имён сигналов, при изменении которых выполнился вызов функции, чтобы сбросить их.
					"Syslog",					    	-- Префикс имени файла.
					60, 							-- Глубина запроса данных [s].
					0.1,							-- Интервал запроса данных [s];	
                   {	"IBE_Teh.Timestamp",				--1
						"IBE_Teh.EventNumber",				--2
						"IBE_Teh.Severity",					--3
						"IBE_Teh.EventID",					--4
						"IBE_Teh.EventName",				--5
						"IBE_Teh.ServerAddress",			--6
						"IBE_Teh.ServerHostName",			--7
						"IBE_Teh.SignalSource",				--8
						"IBE_Teh.SignalValue",				--9
						"IBE_Teh.SignalStringValue",		--10
						"IBE_Teh.SignalValueDimension",		--11
						"IBE_Teh.SignalValueUnit",			--12
						"IBE_Teh.SignalType",				--13
						"IBE_Teh.AlarmState",				--14
						"IBE_Teh.OperatorNode",				--15
						"IBE_Teh.OperatorName",				--16
						"IBE_Teh.ThresholdValue",			--17
						"IBE_Teh.SignalDeviation",			--18
						"IBE_Teh.Result",					--19
						"IBE_Teh.Detail",					--20
						"IBE_Teh.StartWrihtSQL"				--21
						},		
					MainServerFlag
			},             
			 true )]]
Core.waitEvents();




-- Формат функции регистрации обработчиков следующий.
-- Core.onExtChange( event_signals, event_function, event_function_arg)
-- event_signals - таблица с перечнем имён сигналов, при изменении которых вызывать обработчик.
-- event_function - функция-обработчик, с единственным аргументом.
-- event_function_arg - аргумент функции-обработчика (может быть любым типом (в том числе и таблицей).

-- Регистрируем обработчик события изменения сигналов.
--[[
Core.onExtChange(
				{"AGPA1_ASArchive.Stop" },		-- Перечень имён сигналов, при изменении которых выполнять вызов функции dump.
				dump,							-- Вызываемая функция
				{
					{},	-- Передаём в обработчик перечень имён сигналов, при изменении которых выполнился вызов функции, чтобы сбросить их.
					"AO",					    -- Префикс имени файла.
					60, 						-- Глубина запроса данных [s].
					0.1,							-- Интервал запроса данных [s];
					MassAlarmValues		-- Перечень имён сохраняемых сигналов.
				}
);

-- Регистрируем обработчик события изменения сигналов.
Core.onExtChange(
				{"AGPA1_ASArchive.Start" },		-- Перечень имён сигналов, при изменении которых выполнять вызов функции dump.
				dump,							-- Вызываемая функция
				{
					{},	-- Передаём в обработчик перечень имён сигналов, при изменении которых выполнился вызов функции, чтобы сбросить их.
					"Start",					    -- Префикс имени файла.
					20, 						-- Глубина запроса данных [s].
					0.1,							-- Интервал запроса данных [s];
					MassAlarmValues		-- Перечень имён сохраняемых сигналов.
				}
);
--]]

--[[
-- Регистрируем обработчик события изменения других сигналов.
Core.onExtChange(
				{"Critical_1", "Critical_2"},	-- Перечень имён сигналов, при изменении которых выполнять вызов функции dump.
				dump,							-- Вызываемая функция
				{
					{"Critical_1", "Critical_2"},-- Передаём в обработчик перечень имён сигналов, при изменении которых выполнился вызов функции, чтобы сбросить их.
					"Critical",					-- Префикс имени файла.
					100, 						-- Глубина запроса данных [s].
					1,							-- Интервал запроса данных [s];
					{"Real_3", "Real_4"}		-- Перечень имён сохраняемых сигналов.
				}
);
]]
-- Переходим к ожиданию событий.
