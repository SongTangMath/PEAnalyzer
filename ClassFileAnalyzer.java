import java.util.*;
import java.io.*;

public class ClassFileAnalyzer {

    public static final char ACC_PUBLIC = 0x0001;
    public static final char ACC_PRIVATE = 0x0002;
    public static final char ACC_PROTECTED = 0x0004;
    public static final char ACC_STATIC = 0x0008;
    public static final char ACC_FINAL = 0x0010;
    public static final char ACC_SUPER = 0x0020;
    public static final char ACC_VOLATILE = 0x0040;
    public static final char ACC_TRANSIENT = 0x0080;
    public static final char ACC_INTERFACE = 0x0200;
    public static final char ACC_ABSTRACT = 0x0400;
    public static final char ACC_SYNTHETIC = 0x1000;
    public static final char ACC_ANNOTATION = 0x2000;
    public static final char ACC_ENUM = 0x4000;

    public static final byte T_BOOLEAN = 4;
    public static final byte T_CHAR = 5;
    public static final byte T_FLOAT = 6;
    public static final byte T_DOUBLE = 7;
    public static final byte T_BYTE = 8;
    public static final byte T_SHORT = 9;
    public static final byte T_INT = 10;
    public static final byte T_LONG = 11;

    public static final byte ITEM_TOP = 0;
    public static final byte ITEM_INTEGER = 1;
    public static final byte ITEM_FLOAT = 2;
    public static final byte ITEM_NULL = 5;
    public static final byte ITEM_UninitializedThis = 6;
    public static final byte ITEM_OBJECT = 7;
    public static final byte ITEM_Uninitialized = 8;
    public static final byte ITEM_DOUBLE = 3;
    public static final byte ITEM_LONG = 4;

    public static String getItemName(byte tag) {

        switch (tag) {
            case ITEM_TOP:
                return "ITEM_TOP";
            case ITEM_INTEGER:
                return "ITEM_INTEGER";
            case ITEM_FLOAT:
                return "ITEM_FLOAT";
            case ITEM_NULL:
                return "ITEM_NULL";
            case ITEM_UninitializedThis:
                return "ITEM_UninitializedThis";
            case ITEM_OBJECT:
                return "ITEM_OBJECT";
            case ITEM_Uninitialized:
                return "ITEM_Uninitialized";
            case ITEM_DOUBLE:
                return "ITEM_DOUBLE";
            case ITEM_LONG:
                return "ITEM_LONG";

            default:
                return "";
        }
    }

    public static String getTypeName(byte data) {
        switch (data) {
            case T_BOOLEAN:
                return "T_BOOLEAN";
            case T_CHAR:
                return "T_CHAR";
            case T_FLOAT:
                return "T_FLOAT";
            case T_DOUBLE:
                return "T_DOUBLE";
            case T_BYTE:
                return "T_BYTE";
            case T_SHORT:
                return "T_SHORT";
            case T_INT:
                return "T_INT";
            case T_LONG:
                return "T_LONG";
            default:
                return "unknown type";
        }
    }

    public static String getAccessFlagsString(char accessFlags) {
        StringBuilder sb = new StringBuilder("");
        if ((accessFlags & ACC_PUBLIC) != 0)
            sb.append("ACC_PUBLIC ");
        if ((accessFlags & ACC_PRIVATE) != 0)
            sb.append("ACC_PRIVATE ");
        if ((accessFlags & ACC_PROTECTED) != 0)
            sb.append("ACC_PROTECTED ");
        if ((accessFlags & ACC_STATIC) != 0)
            sb.append("ACC_STATIC ");
        if ((accessFlags & ACC_FINAL) != 0)
            sb.append("ACC_FINAL ");
        if ((accessFlags & ACC_SUPER) != 0)
            sb.append("ACC_SUPER ");
        if ((accessFlags & ACC_VOLATILE) != 0)
            sb.append("ACC_VOLATILE ");
        if ((accessFlags & ACC_TRANSIENT) != 0)
            sb.append("ACC_TRANSIENT ");
        if ((accessFlags & ACC_INTERFACE) != 0)
            sb.append("ACC_INTERFACE ");
        if ((accessFlags & ACC_ABSTRACT) != 0)
            sb.append("ACC_ABSTRACT ");
        if ((accessFlags & ACC_SYNTHETIC) != 0)
            sb.append("ACC_SYNTHETIC ");
        if ((accessFlags & ACC_ANNOTATION) != 0)
            sb.append("ACC_ANNOTATION ");
        if ((accessFlags & ACC_ENUM) != 0)
            sb.append("ACC_ENUM ");
        return sb.toString();

    }

    public static long getUnsignedInt(int data) {
        return data >= 0 ? data : data + 4294967296L;
    }

    public static int getUnsignedChar(char data) {
        return data >= 0 ? data : data + 65536;
    }

    public static short getUnsignedByte(byte data) {
        return (short)(data >= 0 ? data : data + 256);
    }

    public static void analyze_verification_type_info(DataInputStream dis) throws IOException {
        byte tag = dis.readByte();
        System.out.print(getItemName(tag) + " ");
        switch (tag) {

            case ITEM_TOP:
            case ITEM_INTEGER:
            case ITEM_FLOAT:
            case ITEM_NULL:
            case ITEM_UninitializedThis:
                break;
            case ITEM_OBJECT:
                char cpool_index = dis.readChar();
                System.out.println("cpool_index= " + (int)cpool_index);
                break;
            case ITEM_Uninitialized:
                char offset = dis.readChar();
                System.out.println("offset= " + (int)offset);
                break;
            case ITEM_DOUBLE:
            case ITEM_LONG:
                break;

        }
    }

    public static TreeMap<Integer, String> getCodeMnemonic() {
        TreeMap<Integer, String> codeMnemonic = new TreeMap<Integer, String>();
        codeMnemonic.put(0x00, "nop");
        codeMnemonic.put(0x01, "aconst_null");
        codeMnemonic.put(0x02, "iconst_m1");
        codeMnemonic.put(0x03, "iconst_0");
        codeMnemonic.put(0x04, "iconst_1");
        codeMnemonic.put(0x05, "iconst_2");
        codeMnemonic.put(0x06, "iconst_3");
        codeMnemonic.put(0x07, "iconst_4");
        codeMnemonic.put(0x08, "iconst_5");
        codeMnemonic.put(0x09, "lconst_0");
        codeMnemonic.put(0x0a, "lconst_1");
        codeMnemonic.put(0x0b, "fconst_0");
        codeMnemonic.put(0x0c, "fconst_1");
        codeMnemonic.put(0x0d, "fconst_2");
        codeMnemonic.put(0x0e, "dconst_0");
        codeMnemonic.put(0x0f, "dconst_1");
        codeMnemonic.put(0x10, "bipush");
        codeMnemonic.put(0x11, "sipush");
        codeMnemonic.put(0x12, "ldc");
        codeMnemonic.put(0x13, "ldc_w");
        codeMnemonic.put(0x14, "ldc2_w");
        codeMnemonic.put(0x15, "iload");
        codeMnemonic.put(0x16, "lload");
        codeMnemonic.put(0x17, "fload");
        codeMnemonic.put(0x18, "dload");
        codeMnemonic.put(0x19, "aload");
        codeMnemonic.put(0x1a, "iload_0");
        codeMnemonic.put(0x1b, "iload_1");
        codeMnemonic.put(0x1c, "iload_2");
        codeMnemonic.put(0x1d, "iload_3");
        codeMnemonic.put(0x1e, "lload_0");
        codeMnemonic.put(0x1f, "lload_1");
        codeMnemonic.put(0x20, "lload_2");
        codeMnemonic.put(0x21, "lload_3");
        codeMnemonic.put(0x22, "fload_0");
        codeMnemonic.put(0x23, "fload_1");
        codeMnemonic.put(0x24, "fload_2");
        codeMnemonic.put(0x25, "fload_3");
        codeMnemonic.put(0x26, "dload_0");
        codeMnemonic.put(0x27, "dload_1");
        codeMnemonic.put(0x28, "dload_2");
        codeMnemonic.put(0x29, "dload_3");
        codeMnemonic.put(0x2a, "aload_0");
        codeMnemonic.put(0x2b, "aload_1");
        codeMnemonic.put(0x2c, "aload_2");
        codeMnemonic.put(0x2d, "aload_3");
        codeMnemonic.put(0x2e, "iaload");
        codeMnemonic.put(0x2f, "laload");
        codeMnemonic.put(0x30, "faload");
        codeMnemonic.put(0x31, "daload");
        codeMnemonic.put(0x32, "aaload");
        codeMnemonic.put(0x33, "baload");
        codeMnemonic.put(0x34, "caload");
        codeMnemonic.put(0x35, "saload");
        codeMnemonic.put(0x36, "istore");
        codeMnemonic.put(0x37, "lstore");
        codeMnemonic.put(0x38, "fstore");
        codeMnemonic.put(0x39, "dstore");
        codeMnemonic.put(0x3a, "astore");
        codeMnemonic.put(0x3b, "istore_0");
        codeMnemonic.put(0x3c, "istore_1");
        codeMnemonic.put(0x3d, "istore_2");
        codeMnemonic.put(0x3e, "istore_3");
        codeMnemonic.put(0x3f, "lstore_0");
        codeMnemonic.put(0x40, "lstore_1");
        codeMnemonic.put(0x41, "lstore_2");
        codeMnemonic.put(0x42, "lstore_3");
        codeMnemonic.put(0x43, "fstore_0");
        codeMnemonic.put(0x44, "fstore_1");
        codeMnemonic.put(0x45, "fstore_2");
        codeMnemonic.put(0x46, "fstore_3");
        codeMnemonic.put(0x47, "dstore_0");
        codeMnemonic.put(0x48, "dstore_1");
        codeMnemonic.put(0x49, "dstore_2");
        codeMnemonic.put(0x4a, "dstore_3");
        codeMnemonic.put(0x4b, "astore_0");
        codeMnemonic.put(0x4c, "astore_1");
        codeMnemonic.put(0x4d, "astore_2");
        codeMnemonic.put(0x4e, "astore_3");
        codeMnemonic.put(0x4f, "iastore");
        codeMnemonic.put(0x50, "lastore");
        codeMnemonic.put(0x51, "fastore");
        codeMnemonic.put(0x52, "dastore");
        codeMnemonic.put(0x53, "aastore");
        codeMnemonic.put(0x54, "bastore");
        codeMnemonic.put(0x55, "castore");
        codeMnemonic.put(0x56, "sastore");
        codeMnemonic.put(0x57, "pop");
        codeMnemonic.put(0x58, "pop2");
        codeMnemonic.put(0x59, "dup");
        codeMnemonic.put(0x5a, "dup_x1");
        codeMnemonic.put(0x5b, "dup_x2");
        codeMnemonic.put(0x5c, "dup2");
        codeMnemonic.put(0x5d, "dup2_x1");
        codeMnemonic.put(0x5e, "dup2_x2");
        codeMnemonic.put(0x5f, "swap");
        codeMnemonic.put(0x60, "iadd");
        codeMnemonic.put(0x61, "ladd");
        codeMnemonic.put(0x62, "fadd");
        codeMnemonic.put(0x63, "dadd");
        codeMnemonic.put(0x64, "isub");
        codeMnemonic.put(0x65, "lsub");
        codeMnemonic.put(0x66, "fsub");
        codeMnemonic.put(0x67, "dsub");
        codeMnemonic.put(0x68, "imul");
        codeMnemonic.put(0x69, "lmul");
        codeMnemonic.put(0x6a, "fmul");
        codeMnemonic.put(0x6b, "dmul");
        codeMnemonic.put(0x6c, "idiv");
        codeMnemonic.put(0x6d, "ldiv");
        codeMnemonic.put(0x6e, "fdiv");
        codeMnemonic.put(0x6f, "ddiv");
        codeMnemonic.put(0x70, "irem");
        codeMnemonic.put(0x71, "lrem");
        codeMnemonic.put(0x72, "frem");
        codeMnemonic.put(0x73, "drem");
        codeMnemonic.put(0x74, "ineg");
        codeMnemonic.put(0x75, "lneg");
        codeMnemonic.put(0x76, "fneg");
        codeMnemonic.put(0x77, "dneg");
        codeMnemonic.put(0x78, "ishl");
        codeMnemonic.put(0x79, "lshl");
        codeMnemonic.put(0x7a, "ishr");
        codeMnemonic.put(0x7b, "lshr");
        codeMnemonic.put(0x7c, "iushr");
        codeMnemonic.put(0x7d, "lushr");
        codeMnemonic.put(0x7e, "iand");
        codeMnemonic.put(0x7f, "land");
        codeMnemonic.put(0x80, "ior");
        codeMnemonic.put(0x81, "lor");
        codeMnemonic.put(0x82, "ixor");
        codeMnemonic.put(0x83, "lxor");
        codeMnemonic.put(0x84, "iinc");
        codeMnemonic.put(0x85, "i2l");
        codeMnemonic.put(0x86, "i2f");
        codeMnemonic.put(0x87, "i2d");
        codeMnemonic.put(0x88, "l2i");
        codeMnemonic.put(0x89, "l2f");
        codeMnemonic.put(0x8a, "l2d");
        codeMnemonic.put(0x8b, "f2i");
        codeMnemonic.put(0x8c, "f2l");
        codeMnemonic.put(0x8d, "f2d");
        codeMnemonic.put(0x8e, "d2i");
        codeMnemonic.put(0x8f, "d2l");
        codeMnemonic.put(0x90, "d2f");
        codeMnemonic.put(0x91, "i2b");
        codeMnemonic.put(0x92, "i2c");
        codeMnemonic.put(0x93, "i2s");
        codeMnemonic.put(0x94, "lcmp");
        codeMnemonic.put(0x95, "fcmpl");
        codeMnemonic.put(0x96, "fcmpg");
        codeMnemonic.put(0x97, "dcmpl");
        codeMnemonic.put(0x98, "dcmpg");
        codeMnemonic.put(0x99, "ifeq");
        codeMnemonic.put(0x9a, "ifne");
        codeMnemonic.put(0x9b, "iflt");
        codeMnemonic.put(0x9c, "ifge");
        codeMnemonic.put(0x9d, "ifgt");
        codeMnemonic.put(0x9e, "ifle");
        codeMnemonic.put(0x9f, "if_icmpeq");
        codeMnemonic.put(0xa0, "if_icmpne");
        codeMnemonic.put(0xa1, "if_icmplt");
        codeMnemonic.put(0xa2, "if_icmpge");
        codeMnemonic.put(0xa3, "if_icmpgt");
        codeMnemonic.put(0xa4, "if_icmple");
        codeMnemonic.put(0xa5, "if_acmpeq");
        codeMnemonic.put(0xa6, "if_acmpne");
        codeMnemonic.put(0xa7, "goto");
        codeMnemonic.put(0xa8, "jsr");
        codeMnemonic.put(0xa9, "ret");
        codeMnemonic.put(0xaa, "tableswitch");
        codeMnemonic.put(0xab, "lookupswitch");
        codeMnemonic.put(0xac, "ireturn");
        codeMnemonic.put(0xad, "lreturn");
        codeMnemonic.put(0xae, "freturn");
        codeMnemonic.put(0xaf, "dreturn");
        codeMnemonic.put(0xb0, "areturn");
        codeMnemonic.put(0xb1, "return");
        codeMnemonic.put(0xb2, "getstatic");
        codeMnemonic.put(0xb3, "putstatic");
        codeMnemonic.put(0xb4, "getfield");
        codeMnemonic.put(0xb5, "putfield");
        codeMnemonic.put(0xb6, "invokevirtual");
        codeMnemonic.put(0xb7, "invokespecial");
        codeMnemonic.put(0xb8, "invokestatic");
        codeMnemonic.put(0xb9, "invokeinterface");
        codeMnemonic.put(0xba, "invokedynamic");
        codeMnemonic.put(0xbb, "new");
        codeMnemonic.put(0xbc, "newarray");
        codeMnemonic.put(0xbd, "anewarray");
        codeMnemonic.put(0xbe, "arraylength");
        codeMnemonic.put(0xbf, "athrow");
        codeMnemonic.put(0xc0, "checkcast");
        codeMnemonic.put(0xc1, "instanceof");
        codeMnemonic.put(0xc2, "monitorenter");
        codeMnemonic.put(0xc3, "monitorexit");
        codeMnemonic.put(0xc4, "wide");
        codeMnemonic.put(0xc5, "multianewarray");
        codeMnemonic.put(0xc6, "ifnull");
        codeMnemonic.put(0xc7, "ifnonnull");
        codeMnemonic.put(0xc8, "goto_w");
        codeMnemonic.put(0xc9, "jsr_w");
        codeMnemonic.put(0xca, "breakpoint");
        codeMnemonic.put(0xfe, "impdep1");
        codeMnemonic.put(0xff, "impdep2");

        return codeMnemonic;

    }

    public static void analyzeAnnotation(DataInputStream dis, TreeMap<Character, CONSTANT_info> constantPoolMap)
        throws IOException {
        char type_index = dis.readChar();
        char num_element_value_pairs = dis.readChar();
        CONSTANT_Utf8_Info strInfo1 = (CONSTANT_Utf8_Info)constantPoolMap.get(type_index);
        System.out.println(strInfo1.s);
        for (char num_element_value_pairs_index = 0; num_element_value_pairs_index < num_element_value_pairs;
            num_element_value_pairs_index++) {
            char element_name_index = dis.readChar();
            CONSTANT_Utf8_Info strInfo2 = (CONSTANT_Utf8_Info)constantPoolMap.get(element_name_index);
            System.out.println(strInfo2.s);
            byte tag = dis.readByte();
            switch (tag) {
                case 'B':
                case 'C':
                case 'D':
                case 'F':
                case 'I':
                case 'J':
                case 'S':
                case 'Z':
                case 's':
                    char const_value_index = dis.readChar();
                    printInformationFromConstantPoolIndex(constantPoolMap, const_value_index);
                case 'e':
                    char type_name_index = dis.readChar();
                    char const_name_index = dis.readChar();
                    printInformationFromConstantPoolIndex(constantPoolMap, type_name_index);
                    printInformationFromConstantPoolIndex(constantPoolMap, const_name_index);
                case 'c':
                    char class_index = dis.readChar();
                    printInformationFromConstantPoolIndex(constantPoolMap, class_index);
                case '@':
                    char num_values = dis.readChar();
                    for (char annotation_index = 0; annotation_index < num_values; annotation_index++)
                        analyzeAnnotation(dis, constantPoolMap);
                case '[':

            }
        }

    }

    public static void analyzeCode(DataInputStream dis, CodeStatus status) throws IOException {

        int code = getUnsignedByte(dis.readByte());

        TreeMap<Integer, String> map = getCodeMnemonic();
        String mnemonic = map.get((int)code);
        System.out.print(status.codeAnalyzedLength + ": " + mnemonic + " ");
        status.codeAnalyzedLength++;
        switch (mnemonic) {

            case "bipush":
                System.out.print(dis.readByte());
                status.codeAnalyzedLength++;
                break;
            case "aload":
            case "astore":
            case "dload":
            case "dstore":
            case "iload":
            case "istore":
            case "ldc":
            case "lload":
            case "lstore":
            case "ret":
                System.out.print(getUnsignedByte(dis.readByte()));
                status.codeAnalyzedLength++;
                break;

            case "sipush":
                System.out.print(dis.readShort());
                status.codeAnalyzedLength += 2;
                break;

            case "anewarray":
            case "checkcast":
            case "getfield":
            case "getstatic":
            case "goto":
            case "if_acmpeq":
            case "if_acmpne":
            case "if_icmpeq":
            case "if_icmpne":
            case "if_icmplt":
            case "if_icmpgt":
            case "if_icmpge":
            case "if_icmple":
            case "ifeq":
            case "ifne":
            case "iflt":
            case "ifge":
            case "ifgt":
            case "ifle":
            case "ifnonnull":
            case "ifnull":
            case "instanceof":
            case "invokespecial":
            case "invokestatic":
            case "invokevirtual":
            case "jsr":
            case "ldc_w":
            case "ldc2_w":
            case "new":
            case "putfield":
            case "putstatic":
                System.out.print((int)dis.readChar());
                status.codeAnalyzedLength += 2;
                break;

            case "goto_w":
            case "jsr_w":
                System.out.print(getUnsignedInt(dis.readInt()));
                status.codeAnalyzedLength += 4;
                break;
            case "iinc":
                System.out.print(getUnsignedByte(dis.readByte()) + " " + getUnsignedByte(dis.readByte()));
                status.codeAnalyzedLength += 2;
                break;
            case "invokedynamic":
                System.out.print((int)dis.readChar() + " " + dis.readShort());
                status.codeAnalyzedLength += 4;
                break;
            case "invokeinterface":
                System.out.print((int)dis.readChar() + " " + getUnsignedByte(dis.readByte()) + " " + dis.readByte());
                status.codeAnalyzedLength += 4;
                break;
            case "lookupswitch": {
                while (status.codeAnalyzedLength % 4 != 0) {
                    dis.skip(1);
                    status.codeAnalyzedLength++;
                }
                int defaultPos = dis.readInt();
                int npairs = dis.readInt();
                status.codeAnalyzedLength += 8;
                System.out.println("defaultPos= " + defaultPos + " npairs " + npairs + "{");
                for (int i = 0; i < npairs; i++) {
                    int val = dis.readInt();
                    int pos = dis.readInt();
                    status.codeAnalyzedLength += 8;
                    System.out.println("   " + val + ":" + pos);
                }
                System.out.print("}");
                break;
            }
            case "multianewarray":
                char index = dis.readChar();
                byte dimensions = dis.readByte();
                System.out.print("index= " + (int)index + " dimensions= " + getUnsignedByte(dimensions));
                break;
            case "newarray":
                byte atype = dis.readByte();
                status.codeAnalyzedLength++;
                System.out.print(getTypeName(atype));
                break;
            case "tableswitch": {
                while (status.codeAnalyzedLength % 4 != 0) {
                    dis.skip(1);
                    status.codeAnalyzedLength++;
                }
                int defaultPos = dis.readInt();
                int low = dis.readInt();
                int high = dis.readInt();
                status.codeAnalyzedLength += 12;
                System.out.println("defaultPos= " + defaultPos + " npairs " + (high - low + 1) + "{");
                for (int i = low; i <= high; i++) {
                    int pos = dis.readInt();
                    status.codeAnalyzedLength += 4;
                    System.out.println("   " + i + ":" + pos);
                }
                System.out.print("}");
                break;
            }
            case "wide":

                byte nextOperation = dis.readByte();
                status.codeAnalyzedLength++;
                String nextOperationName = map.get((int)nextOperation);
                switch (nextOperationName) {

                    case "iload":
                    case "fload":
                    case "aload":
                    case "lload":
                    case "dload":
                    case "istore":
                    case "fstore":
                    case "astore":
                    case "lstore":
                    case "dstore":
                    case "ret":
                        char nextIndex = dis.readChar();
                        status.codeAnalyzedLength += 2;
                        System.out.print((int)nextIndex);
                        break;
                    case "iinc":
                        System.out.print((int)dis.readChar() + " " + dis.readShort());
                        status.codeAnalyzedLength += 4;
                        break;
                }
                break;

        }
        System.out.println();
    }

    public static void printInformationFromConstantPoolIndex(TreeMap<Character, CONSTANT_info> constantPoolMap,
        char key) {
        CONSTANT_info temp = constantPoolMap.get(key);
        System.out.print((int)key + " ");
        switch (temp.tag) {
            case CONSTANT_info.CONSTANT_Utf8: {
                CONSTANT_Utf8_Info info = (CONSTANT_Utf8_Info)temp;
                System.out.println("CONSTANT_Utf8 " + info.s);
                break;
            }

            case CONSTANT_info.CONSTANT_Integer: {
                CONSTANT_Integer_Info info = (CONSTANT_Integer_Info)temp;
                System.out.println("CONSTANT_Integer " + info.val);
                break;
            }

            case CONSTANT_info.CONSTANT_Float: {
                CONSTANT_Float_Info info = (CONSTANT_Float_Info)temp;
                System.out.println("CONSTANT_Float " + info.val);
                break;
            }

            case CONSTANT_info.CONSTANT_Long: {
                CONSTANT_Long_Info info = (CONSTANT_Long_Info)temp;
                System.out.println("CONSTANT_Long " + info.val);
                break;
            }

            case CONSTANT_info.CONSTANT_Double: {
                CONSTANT_Double_Info info = (CONSTANT_Double_Info)temp;
                System.out.println("CONSTANT_Double " + info.val);
                break;
            }

            case CONSTANT_info.CONSTANT_Class: {
                CONSTANT_Class_Info info = (CONSTANT_Class_Info)temp;
                CONSTANT_Utf8_Info strInfo = (CONSTANT_Utf8_Info)constantPoolMap.get(info.index);
                System.out.println("CONSTANT_Class " + (int)info.index + " " + strInfo.s);
                break;
            }

            case CONSTANT_info.CONSTANT_String: {
                CONSTANT_String_Info info = (CONSTANT_String_Info)temp;
                CONSTANT_Utf8_Info strInfo = (CONSTANT_Utf8_Info)constantPoolMap.get(info.index);
                System.out.println("CONSTANT_String " + (int)info.index + " " + strInfo.s);
                break;
            }

            case CONSTANT_info.CONSTANT_Fieldref: {
                CONSTANT_Fieldref_Info info = (CONSTANT_Fieldref_Info)temp;
                CONSTANT_Class_Info classInfo = (CONSTANT_Class_Info)constantPoolMap.get(info.index1);
                CONSTANT_NameAndType_Info nameAndTypeInfo = (CONSTANT_NameAndType_Info)constantPoolMap.get(info.index2);
                CONSTANT_Utf8_Info strInfo1 = (CONSTANT_Utf8_Info)constantPoolMap.get(classInfo.index);
                CONSTANT_Utf8_Info strInfo2 = (CONSTANT_Utf8_Info)constantPoolMap.get(nameAndTypeInfo.index1);
                CONSTANT_Utf8_Info strInfo3 = (CONSTANT_Utf8_Info)constantPoolMap.get(nameAndTypeInfo.index2);
                System.out.print("CONSTANT_Fieldref ");
                System.out.println("indexes=" + (int)info.index1 + "," + (int)info.index2 + " " + strInfo1.s + "."
                    + strInfo2.s + " " + strInfo3.s);
                break;
            }

            case CONSTANT_info.CONSTANT_Methodref: {
                CONSTANT_Methodref_Info info = (CONSTANT_Methodref_Info)temp;
                CONSTANT_Class_Info classInfo = (CONSTANT_Class_Info)constantPoolMap.get(info.index1);
                CONSTANT_NameAndType_Info nameAndTypeInfo = (CONSTANT_NameAndType_Info)constantPoolMap.get(info.index2);
                CONSTANT_Utf8_Info strInfo1 = (CONSTANT_Utf8_Info)constantPoolMap.get(classInfo.index);
                CONSTANT_Utf8_Info strInfo2 = (CONSTANT_Utf8_Info)constantPoolMap.get(nameAndTypeInfo.index1);
                CONSTANT_Utf8_Info strInfo3 = (CONSTANT_Utf8_Info)constantPoolMap.get(nameAndTypeInfo.index2);
                System.out.print("CONSTANT_Methodref ");
                System.out.println("indexes=" + (int)info.index1 + "," + (int)info.index2 + " " + strInfo1.s + "."
                    + strInfo2.s + " " + strInfo3.s);
                break;
            }

            case CONSTANT_info.CONSTANT_InterfaceMethodref: {
                CONSTANT_InterfaceMethodref_Info info = (CONSTANT_InterfaceMethodref_Info)temp;
                CONSTANT_Class_Info classInfo = (CONSTANT_Class_Info)constantPoolMap.get(info.index1);
                CONSTANT_NameAndType_Info nameAndTypeInfo = (CONSTANT_NameAndType_Info)constantPoolMap.get(info.index2);
                CONSTANT_Utf8_Info strInfo1 = (CONSTANT_Utf8_Info)constantPoolMap.get(classInfo.index);
                CONSTANT_Utf8_Info strInfo2 = (CONSTANT_Utf8_Info)constantPoolMap.get(nameAndTypeInfo.index1);
                CONSTANT_Utf8_Info strInfo3 = (CONSTANT_Utf8_Info)constantPoolMap.get(nameAndTypeInfo.index2);
                System.out.print("CONSTANT_Methodref ");
                System.out.println("indexes=" + (int)info.index1 + "," + (int)info.index2 + " " + strInfo1.s + "."
                    + strInfo2.s + " " + strInfo3.s);
                break;
            }

            case CONSTANT_info.CONSTANT_NameAndType: {
                CONSTANT_NameAndType_Info info = (CONSTANT_NameAndType_Info)temp;
                CONSTANT_Utf8_Info strInfo1 = (CONSTANT_Utf8_Info)constantPoolMap.get(info.index1);
                CONSTANT_Utf8_Info strInfo2 = (CONSTANT_Utf8_Info)constantPoolMap.get(info.index2);
                System.out.print("CONSTANT_NameAndType ");
                System.out.println(
                    "indexes=" + (int)info.index1 + " " + (int)info.index2 + " " + strInfo1.s + " " + strInfo2.s);
                break;
            }

            case CONSTANT_info.CONSTANT_MethodHandle: {
                CONSTANT_MethodHandle_Info info = (CONSTANT_MethodHandle_Info)temp;
                System.out.print("CONSTANT_Fieldref reference_kind=" + info.reference_kind);
                System.out.println(" reference_index=" + (int)info.reference_index);
                break;
            }

            case CONSTANT_info.CONSTANT_MethodType: {
                CONSTANT_MethodType_Info info = (CONSTANT_MethodType_Info)temp;
                CONSTANT_Utf8_Info strInfo = (CONSTANT_Utf8_Info)constantPoolMap.get(info.descriptor_index);
                System.out
                    .println("CONSTANT_MethodType descriptor_index=" + (int)info.descriptor_index + " " + strInfo.s);

                break;
            }

            case CONSTANT_info.CONSTANT_InvokeDynamic: {
                CONSTANT_InvokeDynamic_Info info = (CONSTANT_InvokeDynamic_Info)temp;
                System.out.print("CONSTANT_InvokeDynamic ");
                System.out.println("bootstrap_method_attr_index=" + (int)info.bootstrap_method_attr_index + " "
                    + " name_and_type_index=" + (int)info.name_and_type_index);
                break;
            }

        }

    }

    public static void analyzeMethod(DataInputStream dis, TreeMap<Character, CONSTANT_info> constantPoolMap)
        throws IOException {
        char method_access_flags = dis.readChar();
        char method_name_index = dis.readChar();
        char method_descriptor_index = dis.readChar();
        char method_attribute_count = dis.readChar();
        String method_descriptor_string = ((CONSTANT_Utf8_Info)(constantPoolMap.get(method_descriptor_index))).s;
        String method_name = ((CONSTANT_Utf8_Info)constantPoolMap.get(method_name_index)).s;
        System.out
            .print(getAccessFlagsString(method_access_flags) + " " + method_name + " " + method_descriptor_string);
        System.out.println(" method_attribute_count=" + (int)method_attribute_count);
        for (char method_attribute_index = 0; method_attribute_index < method_attribute_count;
            method_attribute_index++) {
            char method_attribute_name_index = dis.readChar();
            int method_attribute_length = dis.readInt();
            long method_unsigned_attribute_length = getUnsignedInt(method_attribute_length);
            String method_attribute_name_String =
                ((CONSTANT_Utf8_Info)(constantPoolMap.get(method_attribute_name_index))).s;
            System.out.print("attribute" + (int)method_attribute_index + " " + method_attribute_name_String + " length="
                + method_unsigned_attribute_length + " ");
            analyzeAttributes(method_attribute_name_String, method_unsigned_attribute_length, dis, constantPoolMap);
        }
        System.out.println();

    }

    public static void analyze(String filePath) throws Exception {
        File file = new File(filePath);
        long fileLength = -1;
        if (file.exists() && file.isFile())
            fileLength = file.length();
        if (fileLength <= 0)
            return;

        DataInputStream dis = new DataInputStream(new FileInputStream(file));

        int magic = dis.readInt();
        long unsigned_magic = getUnsignedInt(magic);
        System.out.println(String.format("magic: 0x%x", unsigned_magic));
        if (unsigned_magic != 0xcafebabeL) {
            System.out.println("invalid class file");
            dis.close();
            return;
        }
        char minor_version = dis.readChar();
        System.out.println(String.format("minor_version: 0x%x", getUnsignedChar(minor_version)));

        char major_version = dis.readChar();
        System.out.println(String.format("major_version: 0x%x", getUnsignedChar(major_version)));

        char constant_pool = dis.readChar();
        int countstant_pool_count = getUnsignedChar(constant_pool);
        System.out.println(String.format("constant_pool: %d", countstant_pool_count));

        TreeMap<Character, CONSTANT_info> constantPoolMap = new TreeMap<Character, CONSTANT_info>();
        for (char i = 1; i < countstant_pool_count; i++) {
            byte tag = dis.readByte();
            switch (tag) {

                case CONSTANT_info.CONSTANT_Utf8:
                    char len = dis.readChar();
                    byte[] byteBuffer = new byte[len];
                    for (int j = 0; j < len; j++)
                        byteBuffer[j] = dis.readByte();
                    String tempString = new String(byteBuffer, "utf8");
                    constantPoolMap.put(i, new CONSTANT_Utf8_Info(len, tempString));
                    break;

                case CONSTANT_info.CONSTANT_Integer:
                    int tempInt = dis.readInt();
                    constantPoolMap.put(i, new CONSTANT_Integer_Info(tempInt));
                    break;

                case CONSTANT_info.CONSTANT_Float:
                    float tempFloat = dis.readFloat();
                    constantPoolMap.put(i, new CONSTANT_Float_Info(tempFloat));
                    break;

                case CONSTANT_info.CONSTANT_Long:
                    long tempLong = dis.readLong();
                    constantPoolMap.put(i, new CONSTANT_Long_Info(tempLong));
                    i++;
                    break;

                case CONSTANT_info.CONSTANT_Double:
                    double tempDouble = dis.readDouble();
                    constantPoolMap.put(i, new CONSTANT_Double_Info(tempDouble));
                    i++;
                    break;

                case CONSTANT_info.CONSTANT_Class: {
                    char index = dis.readChar();
                    constantPoolMap.put(i, new CONSTANT_Class_Info(index));
                    break;
                }
                case CONSTANT_info.CONSTANT_String: {
                    char index = dis.readChar();
                    constantPoolMap.put(i, new CONSTANT_String_Info(index));
                    break;
                }

                case CONSTANT_info.CONSTANT_Fieldref: {

                }
                case CONSTANT_info.CONSTANT_Methodref: {
                    char index1 = dis.readChar();
                    char index2 = dis.readChar();
                    constantPoolMap.put(i, new CONSTANT_Methodref_Info(index1, index2));
                    break;
                }
                case CONSTANT_info.CONSTANT_InterfaceMethodref: {
                    char index1 = dis.readChar();
                    char index2 = dis.readChar();
                    constantPoolMap.put(i, new CONSTANT_InterfaceMethodref_Info(index1, index2));
                    break;
                }
                case CONSTANT_info.CONSTANT_NameAndType: {
                    char index1 = dis.readChar();
                    char index2 = dis.readChar();
                    constantPoolMap.put(i, new CONSTANT_NameAndType_Info(index1, index2));
                    break;
                }

                case CONSTANT_info.CONSTANT_MethodHandle: {
                    byte reference_kind = dis.readByte();
                    char reference_index = dis.readChar();
                    constantPoolMap.put(i, new CONSTANT_MethodHandle_Info(reference_kind, reference_index));
                    break;
                }

                case CONSTANT_info.CONSTANT_MethodType:

                    char descriptor_index = dis.readChar();
                    constantPoolMap.put(i, new CONSTANT_MethodType_Info(descriptor_index));
                    break;

                case CONSTANT_info.CONSTANT_InvokeDynamic:
                    char bootstrap_method_attr_index = dis.readChar();
                    char name_and_type_index = dis.readChar();
                    constantPoolMap.put(i,
                        new CONSTANT_InvokeDynamic_Info(bootstrap_method_attr_index, name_and_type_index));
                    break;

                default:

                    System.out.println("invalid tag value " + tag + " invalid class file");
                    return;

            }

        }
        for (char key : constantPoolMap.keySet())
            printInformationFromConstantPoolIndex(constantPoolMap, key);
        System.out.println();
        char access_flags = dis.readChar();
        System.out.println("access_flags: " + getAccessFlagsString(access_flags));

        char this_class_index = dis.readChar();
        char super_class_index = dis.readChar();
        CONSTANT_Class_Info this_class_info = (CONSTANT_Class_Info)constantPoolMap.get(this_class_index);
        CONSTANT_Class_Info super_class_info = (CONSTANT_Class_Info)constantPoolMap.get(super_class_index);
        String this_class_name = ((CONSTANT_Utf8_Info)constantPoolMap.get(this_class_info.index)).s;
        String super_class_name = ((CONSTANT_Utf8_Info)constantPoolMap.get(super_class_info.index)).s;
        System.out.println("this class: " + this_class_name);
        System.out.println("super class: " + super_class_name);
        char interfaceCount = dis.readChar();
        System.out.println("interfaceCount= " + (int)interfaceCount);
        for (char count = 0; count < interfaceCount; count++) {
            char interface_index = dis.readChar();
            CONSTANT_Class_Info interface_info = (CONSTANT_Class_Info)constantPoolMap.get(interface_index);
            String interface_name = ((CONSTANT_Utf8_Info)constantPoolMap.get(interface_info.index)).s;
            System.out.println("interface " + (int)count + " " + interface_name);
        }

        System.out.println();
        char fieldCount = dis.readChar();
        System.out.println("fieldCount= " + (int)fieldCount);
        System.out.println();
        for (char count = 0; count < fieldCount; count++) {
            char field_access_flags = dis.readChar();
            char field_name_index = dis.readChar();
            char field_descriptor_index = dis.readChar();
            char field_attribute_count = dis.readChar();
            String field_descriptor_string = ((CONSTANT_Utf8_Info)(constantPoolMap.get(field_descriptor_index))).s;
            String field_name = ((CONSTANT_Utf8_Info)constantPoolMap.get(field_name_index)).s;
            System.out.print((int)count + " " + getAccessFlagsString(field_access_flags) + " " + field_name + " "
                + field_descriptor_string);
            System.out.println(" field_attribute_count=" + (int)field_attribute_count);
            for (char field_attributes_index = 0; field_attributes_index < field_attribute_count;
                field_attributes_index++) {
                char field_attribute_name_index = dis.readChar();
                int field_attribute_length = dis.readInt();
                long field_unsigned_attribute_length = getUnsignedInt(field_attribute_length);
                String field_attribute_name_String =
                    ((CONSTANT_Utf8_Info)(constantPoolMap.get(field_attribute_name_index))).s;
                System.out.print("attribute" + (int)field_attributes_index + " " + field_attribute_name_String
                    + " length=" + field_unsigned_attribute_length + " ");
                analyzeAttributes(field_attribute_name_String, field_unsigned_attribute_length, dis, constantPoolMap);
            }
            System.out.println();
        }

        System.out.println();
        char methodCount = dis.readChar();
        System.out.println("methodCount= " + (int)methodCount);
        System.out.println();
        for (char count = 0; count < methodCount; count++) {
            System.out.print((int)count + " ");
            analyzeMethod(dis, constantPoolMap);
        }

        System.out.println();
        char attributeCount = dis.readChar();
        System.out.println("attributeCount= " + (int)attributeCount);
        for (char attribute_index = 0; attribute_index < attributeCount; attribute_index++) {
            char attribute_name_index = dis.readChar();
            int attribute_length = dis.readInt();
            long unsigned_attribute_length = getUnsignedInt(attribute_length);
            String attribute_name_String = ((CONSTANT_Utf8_Info)(constantPoolMap.get(attribute_name_index))).s;
            System.out.print("attribute" + (int)attribute_index + " " + attribute_name_String + " length="
                + unsigned_attribute_length + " ");
            analyzeAttributes(attribute_name_String, unsigned_attribute_length, dis, constantPoolMap);
        }
        dis.close();
    }

    public static void analyzeAttributes(String attributeName, long unsigned_attribute_length, DataInputStream dis,
        TreeMap<Character, CONSTANT_info> constantPoolMap) throws IOException {

        switch (attributeName) {
            case "Code":

                char max_stack = dis.readChar();
                int max_local = dis.readChar();
                int code_length = dis.readInt();
                long unsigned_code_length = getUnsignedInt(code_length);
                System.out.println("max_stack= " + (int)max_stack + " max_local= " + max_local + " code_length= "
                    + unsigned_code_length);
                CodeStatus status = new CodeStatus(unsigned_code_length, 0);
                while (status.codeAnalyzedLength < status.codeLength)
                    analyzeCode(dis, status);

                char exception_table_length = dis.readChar();
                System.out.println("exception_table_length= " + (int)exception_table_length);
                for (char exception_index = 0; exception_index < exception_table_length; exception_index++) {
                    char start_pc = dis.readChar();
                    char end_pc = dis.readChar();
                    char handler_pc = dis.readChar();
                    char catch_type = dis.readChar();
                    System.out.println("start_pc= " + (int)start_pc + " end_pc= " + (int)end_pc + " handler_pc= "
                        + (int)handler_pc + " catch_type=" + (int)catch_type);
                    if (catch_type != 0) {
                        CONSTANT_Class_Info classInfo = (CONSTANT_Class_Info)constantPoolMap.get(catch_type);
                        CONSTANT_Utf8_Info strInfo = (CONSTANT_Utf8_Info)constantPoolMap.get(classInfo.index);
                        System.out.println(strInfo.s);
                    }

                }
                char code_attributes_count = dis.readChar();
                System.out.println("code_attributes_count= " + (int)code_attributes_count);
                for (char attribute_index = 0; attribute_index < code_attributes_count; attribute_index++) {
                    char code_attribute_name_index = dis.readChar();
                    int code_attribute_length = dis.readInt();
                    long code_unsigned_attribute_length = getUnsignedInt(code_attribute_length);
                    String code_attribute_name_String =
                        ((CONSTANT_Utf8_Info)(constantPoolMap.get(code_attribute_name_index))).s;
                    System.out.print("code_attribute" + (int)attribute_index + " " + code_attribute_name_String
                        + " length=" + code_attribute_length + " ");
                    analyzeAttributes(code_attribute_name_String, code_unsigned_attribute_length, dis, constantPoolMap);
                }
                break;
            case "ConstantValue":
                char constantValueIndex = dis.readChar();
                printInformationFromConstantPoolIndex(constantPoolMap, constantValueIndex);
                break;
            case "Deprecated":
                System.out.println();
                dis.skip(unsigned_attribute_length);
                break;
            case "Exceptions":
                char numberOfExceptions = dis.readChar();
                System.out.print("numberOfExceptions=" + (int)numberOfExceptions + " ");
                for (char exceptionIndex = 0; exceptionIndex < numberOfExceptions; exceptionIndex++) {
                    CONSTANT_Class_Info info = (CONSTANT_Class_Info)constantPoolMap.get(dis.readChar());
                    String exceptionClassName = ((CONSTANT_Utf8_Info)constantPoolMap.get(info.index)).s;
                    System.out.print(exceptionClassName + " ");
                }
                System.out.println();
                break;
            case "EnclosingMethod": {
                char class_index = dis.readChar();
                char method_index = dis.readChar();
                CONSTANT_Class_Info classInfo = (CONSTANT_Class_Info)constantPoolMap.get(class_index);
                CONSTANT_NameAndType_Info nameAndTypeInfo =
                    (CONSTANT_NameAndType_Info)constantPoolMap.get(method_index);
                System.out.print(((CONSTANT_Utf8_Info)constantPoolMap.get(classInfo.index)).s);
                if (nameAndTypeInfo != null) {
                    CONSTANT_Utf8_Info strInfo1 = (CONSTANT_Utf8_Info)constantPoolMap.get(nameAndTypeInfo.index1);
                    CONSTANT_Utf8_Info strInfo2 = (CONSTANT_Utf8_Info)constantPoolMap.get(nameAndTypeInfo.index2);
                    System.out.println(strInfo1.s + " " + strInfo2.s);
                }
            }
                break;
            case "InnerClasses": {
                char number_of_classes = dis.readChar();
                System.out.println("number_of_classes= " + (int)number_of_classes);
                for (char inner_class_index = 0; inner_class_index < number_of_classes; inner_class_index++) {
                    char inner_class_info_index = dis.readChar();
                    char outer_class_info_index = dis.readChar();
                    char inner_name_index = dis.readChar();
                    char inner_class_access_flags = dis.readChar();

                    CONSTANT_Class_Info innerClassInfo =
                        (CONSTANT_Class_Info)constantPoolMap.get(inner_class_info_index);
                    CONSTANT_Class_Info outerClassInfo =
                        (CONSTANT_Class_Info)constantPoolMap.get(outer_class_info_index);

                    String innerClassName1 = ((CONSTANT_Utf8_Info)constantPoolMap.get(innerClassInfo.index)).s;
                    String innerClassName2 = null;
                    if (inner_name_index != 0)
                        innerClassName2 = ((CONSTANT_Utf8_Info)constantPoolMap.get(inner_name_index)).s;
                    String outerClassName = null;
                    if (outerClassInfo != null)
                        outerClassName = ((CONSTANT_Utf8_Info)constantPoolMap.get(outerClassInfo.index)).s;

                    if (inner_name_index != 0)
                        System.out.println("inner_class_short_name= " + innerClassName2);
                    else {

                        System.out.println("name generated for anonymous inner_class_name= " + innerClassName1);
                    }
                    if (outerClassInfo != null)
                        System.out.println("outer_class_name= " + outerClassName);
                    if (inner_class_access_flags != 0)
                        System.out.println("access_flags=" + getAccessFlagsString(inner_class_access_flags));
                }
                break;
            }
            case "LineNumberTable":
                char line_number_table_length = dis.readChar();
                System.out.println("line_number_table_length= " + (int)line_number_table_length);
                for (char line_number_table_index = 0; line_number_table_index < line_number_table_length;
                    line_number_table_index++) {
                    char start_pc = dis.readChar();
                    char line_number = dis.readChar();
                    System.out.println("start_pc= " + (int)start_pc + " line_number= " + (int)line_number);

                }
                break;
            case "LocalVariableTable":
                char local_variable_table_length = dis.readChar();
                System.out.println("local_variable_table_length= " + (int)local_variable_table_length);
                for (char local_variable_table_index = 0; local_variable_table_index < local_variable_table_length;
                    local_variable_table_index++) {
                    char start_pc = dis.readChar();
                    char length = dis.readChar();
                    char name_index = dis.readChar();
                    char descriptor_index = dis.readChar();
                    char index = dis.readChar();
                    System.out.println("start_pc= " + (int)start_pc + " length= " + (int)length + " name_index= "
                        + (int)name_index + " descriptor_index= " + (int)descriptor_index + " index= " + (int)index);

                    CONSTANT_Utf8_Info strInfo1 = (CONSTANT_Utf8_Info)constantPoolMap.get(name_index);
                    CONSTANT_Utf8_Info strInfo2 = (CONSTANT_Utf8_Info)constantPoolMap.get(descriptor_index);
                    System.out.println(strInfo1.s + " " + strInfo2.s);
                }
                break;
            case "StackMapTable":
                char number_of_entries = dis.readChar();
                System.out.println("number_of_entries= " + (int)number_of_entries);
                for (char entry_index = 0; entry_index < number_of_entries; entry_index++) {
                    byte frame_type = dis.readByte();
                    short unsigned_frame_type = getUnsignedByte(frame_type);
                    if (0 <= unsigned_frame_type && unsigned_frame_type <= 63) {
                        System.out.println("frame_type =" + unsigned_frame_type + " SAME");
                    }

                    else if (64 <= unsigned_frame_type && unsigned_frame_type <= 127) {

                        System.out.println("frame_type =" + unsigned_frame_type + " SAME_LOCALS_1_STACK_ITEM");
                        analyze_verification_type_info(dis);
                    } else if (unsigned_frame_type == 247) {
                        char offset_delta = dis.readChar();
                        System.out.println("frame_type =" + unsigned_frame_type
                            + " SAME_LOCALS_1_STACK_ITEM_EXTENDED offset_delta= " + (int)offset_delta);
                        analyze_verification_type_info(dis);

                    }

                    else if (248 <= unsigned_frame_type && unsigned_frame_type <= 250) {

                        char offset_delta = dis.readChar();
                        System.out
                            .println("frame_type =" + unsigned_frame_type + " CHOP offset_delta= " + (int)offset_delta);
                    }

                    else if (unsigned_frame_type == 251) {
                        char offset_delta = dis.readChar();
                        System.out.println("frame_type =" + unsigned_frame_type + " SAME_FRAME_EXTENDED offset_delta= "
                            + (int)offset_delta);

                    }

                    else if (252 <= unsigned_frame_type && unsigned_frame_type <= 254) {

                        char offset_delta = dis.readChar();
                        short unsigned_frame_type_append = getUnsignedByte(frame_type);
                        System.out.println(
                            "frame_type =" + unsigned_frame_type + " APPEND offset_delta= " + (int)offset_delta);
                        for (int i = 0; i < unsigned_frame_type_append - 251; i++)
                            analyze_verification_type_info(dis);
                    } else if (unsigned_frame_type == 255) {
                        char offset_delta = dis.readChar();
                        char number_of_locals = dis.readChar();
                        System.out.println(
                            "frame_type =" + unsigned_frame_type + " FULL_FRAME offset_delta= " + (int)offset_delta);
                        System.out.println("number_of_locals =" + (int)number_of_locals);
                        for (char index = 0; index < number_of_locals; index++)
                            analyze_verification_type_info(dis);
                        char number_of_stack_intems = dis.readChar();
                        System.out.println("number_of_stack_intems =" + (int)number_of_stack_intems);
                        for (char index = 0; index < number_of_stack_intems; index++)
                            analyze_verification_type_info(dis);

                    }
                }
                break;
            case "Signature": {
                char signature_index = dis.readChar();
                CONSTANT_Utf8_Info strInfo = (CONSTANT_Utf8_Info)constantPoolMap.get(signature_index);
                System.out.println(strInfo.s);
                break;
            }

            case "SourceFile": {
                char sourceFile_index = dis.readChar();
                CONSTANT_Utf8_Info strInfo = (CONSTANT_Utf8_Info)constantPoolMap.get(sourceFile_index);
                System.out.println(strInfo.s);
                break;
            }
            case "SourceDebugExtension":
            case "Synthetic":
                System.out.println();
                dis.skip(unsigned_attribute_length);
                break;
            case "LocalVariableTypeTable":
                char local_variable_type_table_length = dis.readChar();
                System.out.println("local_variable_type_table_length= " + (int)local_variable_type_table_length);
                for (char local_variable_type_table_index = 0;
                    local_variable_type_table_index < local_variable_type_table_length;
                    local_variable_type_table_index++) {
                    char start_pc = dis.readChar();
                    char length = dis.readChar();
                    char name_index = dis.readChar();
                    char signature_index = dis.readChar();
                    char index = dis.readChar();
                    System.out.println("start_pc= " + (int)start_pc + " length= " + (int)length + " name_index= "
                        + (int)name_index + " signature_index= " + (int)signature_index + " index= " + (int)index);

                    CONSTANT_Utf8_Info strInfo1 = (CONSTANT_Utf8_Info)constantPoolMap.get(name_index);
                    CONSTANT_Utf8_Info strInfo2 = (CONSTANT_Utf8_Info)constantPoolMap.get(signature_index);
                    System.out.println(strInfo1.s + " " + strInfo2.s);
                }
                break;
            case "RuntimeVisibleAnnotations":
            case "RuntimeInvisibleAnnotations":
            case "RuntimeVisibleParameterAnnotations":
            case "RuntimeInisibleParameterAnnotations":
                char num_annotations = dis.readChar();
                System.out.println("num_annotations= " + (int)num_annotations);
                for (char annotation_index = 0; annotation_index < num_annotations; annotation_index++)
                    analyzeAnnotation(dis, constantPoolMap);
                break;
            case "AnnotationDefault":
                System.out.println();
                dis.skip(unsigned_attribute_length);
                break;
            case "BootstrapMethods":
                char num_bootstrap_methods = dis.readChar();
                System.out.println("num_bootstrap_methods= " + (int)num_bootstrap_methods);
                for (char bootstrap_method_index = 0; bootstrap_method_index < num_bootstrap_methods;
                    bootstrap_method_index++) {
                    char bootstrap_method_ref = dis.readChar();
                    printInformationFromConstantPoolIndex(constantPoolMap, bootstrap_method_ref);
                    char num_bootstrap_arguments = dis.readChar();
                    for (char bootstrap_argument_index = 0; bootstrap_argument_index < num_bootstrap_arguments;
                        bootstrap_argument_index++) {
                        System.out.print(bootstrap_argument_index + " ");
                        printInformationFromConstantPoolIndex(constantPoolMap, dis.readChar());
                    }

                }
            case "RuntimeVisibleTypeAnnotations":
            case "RuntimeInisibleTypeAnnotations":
                char num_type_annotations = dis.readChar();
                System.out.println("num_type_annotations= " + (int)num_type_annotations);
                for (char type_annotation_index = 0; type_annotation_index < num_type_annotations;
                    type_annotation_index++) {

                    byte target_type = dis.readByte();
                    short unsigned_target_type = getUnsignedByte(target_type);
                    switch (unsigned_target_type) {

                        case 0x00:
                        case 0x01: {
                            System.out.print("type_parameter_target ");
                            byte type_parameter_index = dis.readByte();
                            System.out.println(getUnsignedByte(type_parameter_index));
                            break;
                        }
                        case 0x10: {
                            System.out.print("supertype_target");
                            char supertype_index = dis.readChar();
                            System.out.println((int)supertype_index);
                            break;
                        }
                        case 0x11:
                        case 0x12: {
                            System.out.print("type_parameter_bound_target ");
                            byte type_parameter_index = dis.readByte();
                            byte bound_index = dis.readByte();
                            System.out.println("type_parameter_index= " + getUnsignedByte(type_parameter_index)
                                + " bound_index= " + getUnsignedByte(bound_index));
                            break;
                        }
                        case 0x13:
                        case 0x14:
                        case 0x15:
                            System.out.print("empty_target ");
                            break;
                        case 0x16:
                            System.out.print("formal_parameter_target ");
                            char formal_parameter_index = dis.readChar();
                            System.out.println((int)formal_parameter_index);
                            break;
                        case 0x17:
                            System.out.print("throws_target ");
                            char throws_type_index = dis.readChar();
                            System.out.println((int)throws_type_index);
                            break;
                        case 0x40:
                        case 0x41:
                            System.out.print("localvar_target ");
                            char table_length = dis.readChar();
                            System.out.println("table_length= " + (int)table_length);
                            for (char target_index = 0; target_index < table_length; target_index++) {
                                char start_pc = dis.readChar();
                                char length = dis.readChar();
                                char index = dis.readChar();
                                System.out.println(
                                    "start_pc= " + (int)start_pc + " length= " + (int)length + " index= " + (int)index);
                            }
                            break;
                        case 0x42:
                            System.out.print("catch_target ");
                            char exception_table_index = dis.readChar();
                            System.out.println("exception_table_index= " + (int)exception_table_index);
                            break;
                        case 0x43:
                        case 0x44:
                        case 0x45:
                        case 0x46: {
                            System.out.print("offset_target ");
                            char offset = dis.readChar();
                            System.out.println("offset= " + (int)offset);
                            break;
                        }
                        case 0x47:
                        case 0x48:
                        case 0x49:
                        case 0x4a:
                        case 0x4b: {
                            System.out.print("type_argument_target ");
                            char offset = dis.readChar();
                            byte type_argument_index = dis.readByte();
                            System.out.println("offset= " + (int)offset + " type_argument_index= "
                                + getUnsignedByte(type_argument_index));
                            break;

                        }
                    }

                    // target path
                    byte path_length = dis.readByte();
                    short unsigned_path_length = getUnsignedByte(path_length);
                    for (short path_index = 0; path_index < unsigned_path_length; path_index++) {
                        byte type_path_kind = dis.readByte();
                        byte type_argument_index = dis.readByte();
                        System.out.println("type_path_kind= " + getUnsignedByte(type_path_kind)
                            + " type_argument_index= " + getUnsignedByte(type_argument_index));
                    }
                    analyzeAnnotation(dis, constantPoolMap);
                }
                break;
            case "MethodParameters":

            default:
                System.out.println();
                dis.skip(unsigned_attribute_length);
        }
    }

    public static void main(String[] args) throws Exception {

        String filePath = "D:/DispatcherServlet.class";
        if (args.length > 0)
            filePath = args[0];
        analyze(filePath);
    }
}

class CONSTANT_info {
    public static final byte CONSTANT_Utf8 = 1;
    public static final byte CONSTANT_Integer = 3;
    public static final byte CONSTANT_Float = 4;
    public static final byte CONSTANT_Long = 5;
    public static final byte CONSTANT_Double = 6;
    public static final byte CONSTANT_Class = 7;
    public static final byte CONSTANT_String = 8;
    public static final byte CONSTANT_Fieldref = 9;
    public static final byte CONSTANT_Methodref = 10;
    public static final byte CONSTANT_InterfaceMethodref = 11;
    public static final byte CONSTANT_NameAndType = 12;
    public static final byte CONSTANT_MethodHandle = 15;
    public static final byte CONSTANT_MethodType = 16;
    public static final byte CONSTANT_InvokeDynamic = 18;

    public static String getConstantType(byte constantType) {
        switch (constantType) {
            case CONSTANT_Utf8:
                return "CONSTANT_Utf8";
            case CONSTANT_Integer:
                return "CONSTANT_Integer";
            case CONSTANT_Float:
                return "CONSTANT_Float";
            case CONSTANT_Long:
                return "CONSTANT_Long";
            case CONSTANT_Double:
                return "CONSTANT_Double";
            case CONSTANT_Class:
                return "CONSTANT_Class";
            case CONSTANT_String:
                return "CONSTANT_String";
            case CONSTANT_Fieldref:
                return "CONSTANT_Fieldref";
            case CONSTANT_Methodref:
                return "CONSTANT_Methodref";
            case CONSTANT_InterfaceMethodref:
                return "CONSTANT_InterfaceMethodref";
            case CONSTANT_NameAndType:
                return "CONSTANT_NameAndType";
            case CONSTANT_MethodHandle:
                return "CONSTANT_MethodHandle";
            case CONSTANT_MethodType:
                return "CONSTANT_MethodType";
            case CONSTANT_InvokeDynamic:
                return "CONSTANT_InvokeDynamic";
            default:
                return "";
        }
    }

    public byte tag;

}

class CONSTANT_Utf8_Info extends CONSTANT_info {
    public char length;
    public String s;

    public CONSTANT_Utf8_Info(char length, String s) {
        this.tag = CONSTANT_Utf8;
        this.length = length;
        this.s = s;
    }

}

class CONSTANT_Integer_Info extends CONSTANT_info {

    public int val;

    public CONSTANT_Integer_Info(int val) {
        this.tag = CONSTANT_Integer;
        this.val = val;
    }

}

class CONSTANT_Float_Info extends CONSTANT_info {
    public float val;

    public CONSTANT_Float_Info(float val) {
        this.tag = CONSTANT_Double;
        this.val = val;
    }

}

class CONSTANT_Long_Info extends CONSTANT_info {

    public long val;

    public CONSTANT_Long_Info(long val) {
        this.tag = CONSTANT_Long;
        this.val = val;
    }

}

class CONSTANT_Double_Info extends CONSTANT_info {

    public double val;

    public CONSTANT_Double_Info(double val) {
        this.tag = CONSTANT_Double;
        this.val = val;
    }

}

class CONSTANT_Class_Info extends CONSTANT_info {

    public char index;

    public CONSTANT_Class_Info(char index) {
        this.tag = CONSTANT_Class;
        this.index = index;
    }

}

class CONSTANT_String_Info extends CONSTANT_info {

    public char index;

    public CONSTANT_String_Info(char index) {
        this.tag = CONSTANT_String;
        this.index = index;
    }

}

class CONSTANT_Fieldref_Info extends CONSTANT_info {

    public char index1, index2;

    public CONSTANT_Fieldref_Info(char index1, char index2) {
        this.tag = CONSTANT_Fieldref;
        this.index1 = index1;
        this.index2 = index2;
    }

}

class CONSTANT_Methodref_Info extends CONSTANT_info {
    public char index1, index2;

    public CONSTANT_Methodref_Info(char index1, char index2) {
        this.tag = CONSTANT_Methodref;
        this.index1 = index1;
        this.index2 = index2;
    }

}

class CONSTANT_InterfaceMethodref_Info extends CONSTANT_info {
    public char index1, index2;

    public CONSTANT_InterfaceMethodref_Info(char index1, char index2) {
        this.tag = CONSTANT_InterfaceMethodref;
        this.index1 = index1;
        this.index2 = index2;
    }

}

class CONSTANT_NameAndType_Info extends CONSTANT_info {

    public char index1, index2;

    public CONSTANT_NameAndType_Info(char index1, char index2) {
        this.tag = CONSTANT_NameAndType;
        this.index1 = index1;
        this.index2 = index2;
    }

}

class CONSTANT_MethodHandle_Info extends CONSTANT_info {

    public byte reference_kind;
    public char reference_index;

    public CONSTANT_MethodHandle_Info(byte reference_kind, char reference_index) {
        this.tag = CONSTANT_MethodHandle;
        this.reference_kind = reference_kind;
        this.reference_index = reference_index;
    }

}

class CONSTANT_MethodType_Info extends CONSTANT_info {
    public char descriptor_index;

    public CONSTANT_MethodType_Info(char descriptor_index) {
        this.tag = CONSTANT_MethodType;
        this.descriptor_index = descriptor_index;
    }

}

class CONSTANT_InvokeDynamic_Info extends CONSTANT_info {
    public char bootstrap_method_attr_index, name_and_type_index;

    public CONSTANT_InvokeDynamic_Info(char bootstrap_method_attr_index, char name_and_type_index) {
        this.tag = CONSTANT_InvokeDynamic;
        this.bootstrap_method_attr_index = bootstrap_method_attr_index;
        this.name_and_type_index = name_and_type_index;
    }

}

class CodeStatus {

    public long codeLength, codeAnalyzedLength;

    public CodeStatus(long codeLength, long codeAnalyzedLength) {
        super();
        this.codeLength = codeLength;
        this.codeAnalyzedLength = codeAnalyzedLength;
    }

}
