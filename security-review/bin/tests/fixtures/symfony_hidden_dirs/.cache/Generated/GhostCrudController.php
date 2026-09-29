<?php

declare(strict_types=1);

namespace Cache\Generated;

use EasyCorp\Bundle\EasyAdminBundle\Controller\AbstractCrudController;

// Regression fixture for P8: a PHPStan-style result-cache artifact that
// happens to look like a real CRUD controller. Must never be parsed — the
// extractor prunes any directory whose basename starts with "." before it
// ever opens a file inside it.
class GhostCrudController extends AbstractCrudController
{
    public static function getEntityFqcn(): string
    {
        return \Ghost\Entity\NotReal::class;
    }
}
