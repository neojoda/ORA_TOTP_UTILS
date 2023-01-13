create or replace FUNCTION TOTP_GET_CODE(PSECRET IN VARCHAR2, PGAP IN NUMBER) RETURN VARCHAR2
IS
        CBASE32      CONSTANT VARCHAR2(32 CHAR) := 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    VBITS        VARCHAR2(80 CHAR) := ''; --16 char * 5 bits / Bits representing secret position on CBASE32
    VHEXABITS    VARCHAR2(500) := ''; -- VBITS in HEXA representation
    VUTIME       NUMBER(38); -- Unix time / POSIX Time / Epoch time
    VUTIME30CHK  VARCHAR2(16); -- Unix time in 30 secs chunks (Hexa)
    VLUTIME30CHK VARCHAR2(16); -- Unix time in 30 secs chunks (Hexa) - Last Value used
    VUTIMERANGE  NUMBER(38); -- Unix time adjusted with Gap secs
    VMAC         RAW(100);
    VOFFSET      NUMBER;
    VP1          NUMBER;
    VP2          NUMBER := POWER(2, 31) - 1;
    VOUTKEY VARCHAR2(1000);

    FUNCTION NUM_TO_BIN(PNUM NUMBER) RETURN VARCHAR2 IS
      VBIN VARCHAR2(8);
      VNUM NUMBER := PNUM;
    BEGIN
      IF VNUM = 0
      THEN
        RETURN '0';
      END IF;
      WHILE VNUM > 0
      LOOP
        VBIN := MOD(VNUM, 2) || VBIN;
        VNUM := FLOOR(VNUM / 2);
      END LOOP;
      RETURN VBIN;
    END NUM_TO_BIN;

    FUNCTION BIN_TO_HEX (input_bin IN VARCHAR2) RETURN VARCHAR2 IS
       hex     VARCHAR2 (1000) ;
       sub_bin VARCHAR2 (4) ;
       i       INTEGER :=1 ;
       l_input_bin VARCHAR2(1000);
       mod_result NUMBER;
    begin
    
       l_input_bin := input_bin;
       
       mod_result := MOD(LENGTH(l_input_bin),4);
       
       IF mod_result > 0 THEN
        SELECT LPAD(input_bin, LENGTH(input_bin) + (4-mod_result), '0') 
        INTO l_input_bin 
        FROM DUAL;
       END IF;
    
       sub_bin := SUBSTR(l_input_bin, i, 4);
       WHILE sub_bin IS NOT NULL LOOP
          hex := hex ||CASE sub_bin WHEN '1111' THEN 'F' 
                                    WHEN '1110' THEN 'E'
                                    WHEN '1101' THEN 'D'
                                    WHEN '1100' THEN 'C'
                                    WHEN '1011' THEN 'B'
                                    WHEN '1010' THEN 'A'
                                    WHEN '1001' THEN '9'
                                    WHEN '1000' THEN '8'
                                    WHEN '0111' THEN '7'
                                    WHEN '0110' THEN '6'
                                    WHEN '0101' THEN '5'
                                    WHEN '0100' THEN '4'
                                    WHEN '0011' THEN '3'
                                    WHEN '0010' THEN '2'
                                    WHEN '0001' THEN '1'
                                    WHEN '0000' THEN '0'
                       END; 
          i := i+4;
          sub_bin := SUBSTR(l_input_bin, i, 4);
       END LOOP;
       RETURN hex;
    END;
    

  BEGIN

    FOR C IN 1 .. LENGTH(PSECRET)
    LOOP
      VBITS := VBITS || LPAD(NUM_TO_BIN(INSTR(CBASE32, SUBSTR(PSECRET, C, 1)) - 1), 5, '0');
    END LOOP;

    VHEXABITS := BIN_TO_HEX(VBITS);

    SELECT EXTRACT(DAY FROM(DIFF)) * 86400 + EXTRACT(HOUR FROM(DIFF)) * 3600 + EXTRACT(MINUTE FROM(DIFF)) * 60 + EXTRACT(SECOND FROM(DIFF)) N INTO VUTIME FROM (SELECT CURRENT_TIMESTAMP - TIMESTAMP '1970-01-01 00:00:00 +00:00' DIFF FROM DUAL);

    VUTIMERANGE := VUTIME - FLOOR(PGAP);

    SELECT LPAD(LTRIM(TO_CHAR(FLOOR(VUTIMERANGE / 30), 'xxxxxxxxxxxxxxxx')), 16, '0') INTO VUTIME30CHK FROM DUAL;
       
    VMAC         := DBMS_CRYPTO.MAC(SRC => HEXTORAW(VUTIME30CHK), TYP => DBMS_CRYPTO.HMAC_SH1, KEY => HEXTORAW(VHEXABITS));
    VOFFSET      := TO_NUMBER(SUBSTR(RAWTOHEX(VMAC), -1, 1), 'x');
    VP1          := TO_NUMBER(SUBSTR(RAWTOHEX(VMAC), VOFFSET * 2 + 1, 8), 'xxxxxxxx');
    
    VOUTKEY := SUBSTR(BITAND(VP1, VP2), -6, 6);
    
    RETURN VOUTKEY;
    
    
  END TOTP_GET_CODE;
