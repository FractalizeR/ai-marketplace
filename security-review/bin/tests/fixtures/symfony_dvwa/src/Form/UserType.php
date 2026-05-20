<?php

declare(strict_types=1);

namespace App\Form;

use App\Entity\User;
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\EmailType;
use Symfony\Component\Form\Extension\Core\Type\PasswordType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;

class UserType extends AbstractType
{
    public function buildForm(FormBuilderInterface $builder, array $options): void
    {
        $builder
            ->add('email', EmailType::class)
            ->add('password', PasswordType::class);
    }

    public function configureOptions(OptionsResolver $resolver): void
    {
        // VULN: mass_assignment id=DVWA-09
        // `allow_extra_fields=true` opens the door to `?roles[]=ROLE_ADMIN` and
        // `?apiKey=...` posted alongside legitimate fields — the form binds them
        // straight onto the User entity. `csrf_protection=false` is the second
        // half of the chain that anchors VULN id=DVWA-08 (missing_csrf).
        // Sink_kind=mass_assignment, root_cause_family=injection.
        $resolver->setDefaults([
            'data_class'         => User::class,
            'csrf_protection'    => false,
            'allow_extra_fields' => true,
        ]);
    }
}
