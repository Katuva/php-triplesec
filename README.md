## php-triplesec

PHP implementation of [Triplesec](https://keybase.io/triplesec) v4.


## Installation

### Requirements

- php >= 7.2
- ext-scrypt >= 1.4.2

### Composer Install

    composer install katuva/php-triplesec

## Usage

    <?php
    
    require __DIR__.'/vendor/autoload.php';
    
    echo \Katuva\TripleSec::encrypt('this is the secret message', 's3cr3tk3y') . "\n";