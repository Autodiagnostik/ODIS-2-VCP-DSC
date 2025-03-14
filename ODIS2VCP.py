#!/usr/bin/python
"""
ODIS2VCP

Tento skript slouží k převodu datasetu z formátu ODIS do formátu VCP systému.
Umožňuje také úpravu dat a aktualizaci CRC.

Použití:
    python odis_to_vcp_converter.py input.xml [--output output.xml] [--raw] [--modinput modified.bin]

Autor: Pavel Kloc
"""

import xml.etree.ElementTree as ET
import argparse
import binascii
import os
import re
import sys
import crcmod
import logging
from typing import List, Optional, Dict, Tuple, BinaryIO, TextIO, Any

# Nastavení logování
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Konstanty
CRC32_POLYNOMIAL = 0x104c11db7
CRC32_INIT_VALUE = 0
CRC32_XOR_OUT = 0xFFFFFFFF


class DatasetODIS:
    """
    Třída reprezentující dataset z ODIS formátu.
    """
    def __init__(self, data: bytes, address: int, start_address: int) -> None:
        """
        Inicializace datasetu ODIS.
        
        Args:
            data: Binární data datasetu
            address: Diagnostická adresa
            start_address: Počáteční adresa
        """
        self.data = data
        self.address = address
        self.start_address = start_address
        self.name: Optional[str] = None
        self.version: Optional[str] = None
        self.login: Optional[str] = None
    
    def __str__(self) -> str:
        """Textová reprezentace datasetu pro ladění."""
        return f"DatasetODIS(name={self.name}, address=0x{self.address:x}, size={len(self.data)})"


class ConversionResult:
    """
    Třída obsahující výsledek konverze z ODIS do VCP.
    """
    def __init__(self, dataset: DatasetODIS, vcp: str) -> None:
        """
        Inicializace výsledku konverze.
        
        Args:
            dataset: Původní dataset ODIS
            vcp: Výsledný VCP XML řetězec
        """
        self.dataset = dataset
        self.vcp = vcp
    
    def __str__(self) -> str:
        """Textová reprezentace výsledku konverze pro ladění."""
        return f"ConversionResult(dataset={self.dataset}, vcp_size={len(self.vcp)})"


def parse_arguments() -> argparse.Namespace:
    """
    Zpracování argumentů příkazové řádky.
    
    Returns:
        Namespace s argumenty
    """
    parser = argparse.ArgumentParser(
        description='Konverze ODIS XML datasetu do formátu VCP nebo RAW binárního formátu.'
    )

    parser.add_argument(
        'input', 
        metavar='<input>', 
        type=argparse.FileType('r'), 
        help='ODIS XML soubor'
    )
    parser.add_argument(
        '--output', 
        metavar='<output>', 
        type=argparse.FileType('w'), 
        help='Výstupní soubor (nebo stdout)'
    )
    parser.add_argument(
        '--raw', '-r', 
        action='store_true', 
        help='Výstup v RAW binárním formátu místo VCP'
    )
    parser.add_argument(
        '--modinput', '-m', 
        metavar='<input>', 
        type=argparse.FileType('rb'), 
        help='Modifikovaný binární soubor pro nahrazení dat'
    )
    
    return parser.parse_args()


def parse_odis_file(xml_content: str) -> List[DatasetODIS]:
    """
    Parsování XML souboru formátu ODIS.
    
    Args:
        xml_content: Obsah XML souboru
    
    Returns:
        Seznam datasetů ODIS
    
    Raises:
        ET.ParseError: Pokud XML není validní
    """
    try:
        tree = ET.fromstring(xml_content)
    except ET.ParseError as e:
        logger.error(f"Chyba při parsování XML: {e}")
        raise

    datasets: List[DatasetODIS] = []

    for param in tree.iter('PARAMETER_DATA'):
        try:
            # Získání atributů s defaultními hodnotami pro případ chybějících dat
            diag_addr_str = param.get('DIAGNOSTIC_ADDRESS', '0')
            start_addr_str = param.get('START_ADDRESS', '0')
            
            dataset = DatasetODIS(
                data=convert_to_binary(param.text),
                address=int(diag_addr_str, 16),
                start_address=int(start_addr_str, 16)
            )

            dataset.name = param.get('ZDC_NAME')
            dataset.version = param.get('ZDC_VERSION')
            dataset.login = param.get('LOGIN')

            datasets.append(dataset)
            logger.debug(f"Parsován dataset: {dataset}")
        except (ValueError, TypeError, binascii.Error) as e:
            logger.warning(f"Chyba při zpracování datasetu: {e}")
            # Pokračujeme s dalšími datasety

    if not datasets:
        logger.warning("Nebyly nalezeny žádné datasety v ODIS souboru")
        
    return datasets


def convert_to_binary(hex_string: Optional[str]) -> bytes:
    """
    Převod hexadecimálního řetězce na binární data.
    
    Args:
        hex_string: Hexadecimální řetězec, může obsahovat 0x, mezery, nebo čárky
    
    Returns:
        Binární data
    """
    if hex_string is None:
        return bytes()

    # Odstranění 0x, mezer a čárek
    clean_string = hex_string.replace('0x', '')
    clean_string = re.sub(r'\s', '', clean_string)
    clean_string = clean_string.replace(',', '')
    
    try:
        return binascii.unhexlify(clean_string)
    except binascii.Error as e:
        logger.error(f"Chyba při převodu hex na bin: {e}")
        raise


def update_crc(dataset: DatasetODIS, new_data: bytes) -> int:
    """
    Aktualizace dat v datasetu včetně přepočítání CRC.
    
    Args:
        dataset: Dataset k aktualizaci
        new_data: Nová binární data
    
    Returns:
        Nová hodnota CRC
    """
    # Vytvoření funkce pro výpočet CRC32
    crc32_func = crcmod.mkCrcFun(
        CRC32_POLYNOMIAL, 
        initCrc=CRC32_INIT_VALUE, 
        xorOut=CRC32_XOR_OUT
    )
    
    # Nahrazení dat v datasetu
    dataset.data = new_data
    
    # Výpočet a aktualizace CRC (posledních 4 byte)
    base_data = dataset.data[:-4]
    new_crc = crc32_func(base_data)
    
    # Aktualizace dat s novou CRC
    dataset.data = base_data + new_crc.to_bytes(4, byteorder='little')
    
    return new_crc


def convert_to_vcp(datasets: List[DatasetODIS], input_name: str) -> List[ConversionResult]:
    """
    Konverze ODIS datasetů do formátu VCP.
    
    Args:
        datasets: Seznam ODIS datasetů
        input_name: Název vstupního souboru (bez přípony)
    
    Returns:
        Seznam výsledků konverze
    """
    return [convert_dataset_to_vcp(dataset, input_name) for dataset in datasets]


def convert_dataset_to_vcp(dataset: DatasetODIS, input_name: str) -> ConversionResult:
    """
    Konverze jednoho ODIS datasetu do VCP formátu.
    
    Args:
        dataset: ODIS dataset
        input_name: Název vstupního souboru (bez přípony)
    
    Returns:
        Výsledek konverze
    """
    # Vytvoření kořenového elementu
    root = ET.Element('SW-CNT')

    # Identifikační sekce
    ident = ET.SubElement(root, 'IDENT')

    # Použití jména datasetu nebo vygenerování jména z názvu souboru a adresy
    name = dataset.name or f'{input_name}-{dataset.address:x}'

    # Přidání identifikačních údajů
    ET.SubElement(ident, 'LOGIN').text = dataset.login or ''
    ET.SubElement(ident, 'DATAIID').text = name
    ET.SubElement(ident, 'VERSION-INHALT').text = dataset.version or ''

    # Sekce s daty
    datasets_section = ET.SubElement(root, 'DATENBEREICHE')
    data_section = ET.SubElement(datasets_section, 'DATENBEREICH')

    # Přidání informací o datech
    ET.SubElement(data_section, 'DATEN-NAME').text = name
    ET.SubElement(data_section, 'DATEN-FORMAT_NAME').text = 'DFN_HEX'
    ET.SubElement(data_section, 'START-ADR').text = f"0x{dataset.start_address:x}"

    # Velikost dat
    size = len(dataset.data)
    ET.SubElement(data_section, 'GROESSE-DEKOMPRIMIERT').text = f"0x{size:x}"
    
    # Převod binárních dat do hexadecimální reprezentace oddělené čárkami
    hex_data = ','.join([f"0x{b:02x}" for b in dataset.data])
    ET.SubElement(data_section, 'DATEN').text = hex_data

    # Převod na řetězec
    vcp_xml = ET.tostring(root, encoding="unicode")
    
    return ConversionResult(dataset, vcp_xml)


def export_output(
    converted: List[ConversionResult], 
    args: argparse.Namespace, 
    input_name: str,
    new_crc: Optional[int] = None
) -> None:
    """
    Export výsledku konverze do souboru.
    
    Args:
        converted: Seznam výsledků konverze
        args: Argumenty příkazové řádky
        input_name: Název vstupního souboru (bez přípony)
        new_crc: Nová hodnota CRC (pokud byla vypočítána)
    """
    if not converted:
        logger.warning("Žádná data k exportu")
        return
        
    try:
        if args.raw:
            # Export RAW binárního formátu
            output_filename = f'RAW_{input_name}.bin'
            output = args.output or open(output_filename, 'wb')
            
            with output:
                output.write(converted[0].dataset.data)
                
            logger.info(f"Exportován RAW binární soubor: {output_filename}")
            
        elif args.modinput:
            # Export modifikovaného VCP
            modinput_name = os.path.splitext(os.path.basename(args.modinput.name))[0]
            output_filename = f'VCP_mod_{input_name}_by_{modinput_name}.xml'
            output = args.output or open(output_filename, 'w')
            
            with output:
                output.write(converted[0].vcp)
                
            if new_crc:
                logger.info(f"Exportován modifikovaný VCP XML soubor: {output_filename}, aktualizovaný CRC: 0x{new_crc:08x}")
            else:
                logger.info(f"Exportován modifikovaný VCP XML soubor: {output_filename}")
                
        else:
            # Export standardního VCP
            output_filename = f'VCP_converted_{input_name}.xml'
            output = args.output or open(output_filename, 'w')
            
            with output:
                output.write(converted[0].vcp)
                
            logger.info(f"Exportován VCP XML soubor: {output_filename}")
            
    except IOError as e:
        logger.error(f"Chyba při zápisu výstupu: {e}")
        raise


def main() -> None:
    """
    Hlavní funkce programu.
    """
    try:
        # Zpracování argumentů
        args = parse_arguments()
        
        # Výpis ladících informací
        logger.info(f"Zpracovávám soubor: {args.input.name}")
        
        # Načtení a parsování ODIS souboru
        with args.input:
            xml_content = args.input.read()
        
        datasets = parse_odis_file(xml_content)
        if not datasets:
            logger.error("Nebyly nalezeny žádné datasety, ukončuji")
            return
            
        # Získání názvu vstupního souboru bez přípony
        input_name = os.path.splitext(os.path.basename(args.input.name))[0]
        
        # Modifikace dat, pokud je zadán --modinput
        new_crc = None
        if args.modinput and datasets:
            with args.modinput:
                new_data = args.modinput.read()
                
            logger.info(f"Modifikuji data z: {args.modinput.name}")
            new_crc = update_crc(datasets[0], new_data)
            logger.info(f"Nová CRC: 0x{new_crc:08x}")
        
        # Konverze na VCP formát
        converted = convert_to_vcp(datasets, input_name)
        
        # Export výsledku
        export_output(converted, args, input_name, new_crc)
        
        logger.info("Konverze dokončena úspěšně")
        
    except Exception as e:
        logger.error(f"Chyba při konverzi: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()