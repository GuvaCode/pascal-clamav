program ex;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}
  cthreads,
  {$ENDIF}
  classes, sysutils, clamav, math;
var
  virname  : PChar;
  filename : PChar;
  engine   : Pointer;
  sigs, size: Cardinal;
  mb: single;
  ret : integer;
  options: cl_scan_options;

procedure memset(dstpp: Pointer; c: byte; len: SizeInt);
begin
 {$IfDef cpui386}
  asm
    movl dstpp,%edi
    movl len,%ecx
    dec %ecx
    cld
    movb c,%al
    rep stosb
  end;
  {$Else}
  asm
    movq dstpp,%rdi
    movq len,%rcx
    dec %ecx
    cld
    movb c,%al
    rep stosb
  end;
  {$EndIf}
end;


begin
  SetExceptionMask([exInvalidOp, exDenormalized, exZeroDivide, exOverflow, exUnderflow, exPrecision]);

  if (argc < 2) then
  begin
    writeln( Format('Usage: %s file', [argv[0]]) );
    exit;
  end;

  filename := argv[1];

  if FileExists(argv[1]) = false then
  begin
    writeln( Format( 'Can''t open file %s', [argv[1]] ));
    exit;
  end;

  ret := integer(cl_init(CL_INIT_DEFAULT));

  if not ret = integer(CL_SUCCESS) then
  begin
    writeln( Format( 'Can''t initialize libclamav: %s', [cl_strerror(ret)] ));
    exit;
  end else
  engine := cl_engine_new;

  (* load all available databases from default directory *)

  if  cl_load(cl_retdbdir,pcl_engine(Engine),@sigs,CL_DB_OFFICIAL) > CL_SUCCESS then
  begin
    writeln( Format( 'cl_load: %s', [cl_strerror(Integer(ret))] ));
    cl_engine_free(engine);
    exit;
  end;

  writeln(Format( 'Loaded %u signatures.', [sigs] ));

  (* build engine *)
  ret := integer(cl_engine_compile(engine));
  if not ret = Integer(CL_SUCCESS) then
  begin
    writeln(Format('Database initialization error: %s', [cl_strerror(Integer(ret))]));
    cl_engine_free(engine);
    exit;
  end;

  (* scan file descriptor *)
  memset(@options, 0, sizeof(cl_scan_options));
  options.parse := 0;                             (* enable all parsers *)
  options.general := CL_SCAN_GENERAL_HEURISTICS;  (* enable heuristic alert options *)

  ret := integer(cl_scanfile( filename, @virname, @size, engine, @options));

  if ret = integer(CL_VIRUS) then
  begin
    writeln(Format('Virus detected: %s', [virname]));
  end else
  if ret = integer(CL_CLEAN) then
  begin
    writeln('No virus detected.');
  end else
  begin
    writeln(Format('Error: %s', [cl_strerror(integer(ret))]));
    cl_engine_free(engine);
    exit;
  end;

  (* free memory *)
  cl_engine_free(engine);

  (* calculate size of scanned data *)
  mb := size * (CL_COUNT_PRECISION / 1024) / 1024.0;
  writeln(Format ('Data scanned: %2.2 MB', [mb]));

end.

